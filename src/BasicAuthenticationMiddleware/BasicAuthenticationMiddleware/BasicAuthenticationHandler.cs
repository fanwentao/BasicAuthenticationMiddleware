using System;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;

namespace BasicAuthenticationMiddleware
{
    public class BasicAuthenticationHandler : AuthenticationHandler<BasicAuthenticationOptions>
    {
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
                if (string.IsNullOrEmpty(authorization))
                {
                    _logger.WriteInformation("Authorization not found.");
                    return null;
                }

                // "authorization header schema: Basic ....."
                if (!authorization.StartsWith("Basic", StringComparison.OrdinalIgnoreCase))
                {
                    return null;
                }

                var authorizationParameter = authorization.Substring("Baisc ".Length).Trim();

                if (string.IsNullOrEmpty(authorizationParameter))
                {
                    _logger.WriteInformation("Authorization value is empty.");
                    return null;
                }

                var tuple = ExtractAuthorizationParameter(authorizationParameter);



                var context = new BasicAuthenticationContext(tuple.Item1, tuple.Item2);
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
            byte[] protectedData;
            try
            {
                protectedData = Convert.FromBase64String(authorizationParameter);
            }
            catch (FormatException)
            {
                return null;
            }

            string decodedData;
            try
            {
                decodedData = Encoding.ASCII.GetString(protectedData);
            }
            catch (DecoderFallbackException)
            {
                return null;
            }

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
