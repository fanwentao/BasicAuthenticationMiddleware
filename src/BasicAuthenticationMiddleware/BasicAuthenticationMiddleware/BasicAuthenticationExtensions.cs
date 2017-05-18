using System;
using Owin;

namespace BasicAuthenticationMiddleware
{
    public static class BasicAuthenticationExtensions
    {
        public static IAppBuilder UseBasicAuthentication(this IAppBuilder app, BasicAuthenticationOptions options)
        {
            if (options == null) throw new ArgumentNullException(nameof(options));
            app.Use(typeof(BasicAuthenticationMiddleware), app, options);
            return app;
        }


    }
}
