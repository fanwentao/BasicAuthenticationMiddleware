using System;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler.Encoder;
using Microsoft.Owin.Security.Infrastructure;

namespace BasicAuthenticationMiddleware
{
    public class BasicAuthenticationHandler : AuthenticationHandler<BasicAuthenticationOptions>
    {
        private const string BasicSchemaPrefix = "Basic ";
        private readonly ILogger _logger;
        public BasicAuthenticationHandler(ILogger logger)
        {
            _logger = logger;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            try
            {
                var authorization = Request.Headers.Get("Authorization");
                if (string.IsNullOrEmpty(authorization) || !authorization.StartsWith(BasicSchemaPrefix, StringComparison.OrdinalIgnoreCase))
                {
                    return null;
                }

                var authorizationParameter = authorization.Substring(BasicSchemaPrefix.Length).Trim();
                if (string.IsNullOrEmpty(authorizationParameter))
                {
                    _logger.WriteInformation("authorization parameter is null or empty.");
                    return null;
                }

                var tuple = ExtractAuthorizationParameter(authorizationParameter);
                if (tuple == null)
                {
                    return null;
                }

                var context = new BasicAuthenticationContext(userName: tuple.Item1, password: tuple.Item2);

                var identity = await Options.AuthenticateBasicCredentials(context);

                if (identity != null)
                {
                    return new AuthenticationTicket(identity, new AuthenticationProperties());
                }
                return null;
            }
            catch (Exception ex)
            {
                _logger.WriteError("Authentication failed.", ex);
                return null;
            }

        }

        private static Tuple<string, string> ExtractAuthorizationParameter(string authorizationParameter)
        {
            var protectedData = TextEncodings.Base64.Decode(authorizationParameter);
            var decodedData = Encoding.ASCII.GetString(protectedData);
            if (string.IsNullOrEmpty(decodedData))
            {
                return null;
            }

            // "username:password"
            var index = decodedData.IndexOf(":", StringComparison.Ordinal);
            if (index == -1)
            {
                return null;
            }

            var credentials = decodedData.Split(':');
            string userName = credentials[0];
            string password = credentials[1];
            return Tuple.Create(userName, password);
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode == 401)
            {
                var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);
                if (challenge != null)
                {
                    Response.Headers.AppendValues("WWW-Authenticate", "Basic realm=" + Options.Realm);
                }
            }
            return Task.CompletedTask;
        }
    }
}
