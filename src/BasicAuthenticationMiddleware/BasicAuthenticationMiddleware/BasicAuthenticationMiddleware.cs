using System;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Infrastructure;
using Owin;

namespace BasicAuthenticationMiddleware
{
    public class BasicAuthenticationMiddleware : AuthenticationMiddleware<BasicAuthenticationOptions>
    {
        private readonly ILogger _logger;

        public BasicAuthenticationMiddleware(
            OwinMiddleware next,
            IAppBuilder app,
            BasicAuthenticationOptions options) : base(next, options)
        {
            if (string.IsNullOrEmpty(Options.Realm))
            {
                throw new ArgumentNullException(nameof(options.Realm));
            }

            _logger = app.CreateLogger<BasicAuthenticationMiddleware>();
        }

        protected override AuthenticationHandler<BasicAuthenticationOptions> CreateHandler()
        {
            return new BasicAuthenticationHandler(_logger);
        }
    }
}
