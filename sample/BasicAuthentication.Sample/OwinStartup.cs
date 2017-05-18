using System.Threading.Tasks;
using Microsoft.Owin;
using Owin;
using System.Web.Http;
using System.Security.Claims;
using BasicAuthenticationMiddleware;

[assembly: OwinStartup(typeof(BasicAuthentication.Sample.OwinStartup))]

namespace BasicAuthentication.Sample
{
    public class OwinStartup
    {
        public static void Configuration(IAppBuilder app)
        {
            var config = new HttpConfiguration();
            config.Routes.MapHttpRoute("Default", "{controller}/{customerID}", new { controller = "values", customerID = RouteParameter.Optional });
            config.MapHttpAttributeRoutes();

            app.UseBasicAuthentication(new BasicAuthenticationOptions
            {
                AuthenticateBasicCredentials = AuthenticateBasicCredentials,
                Realm = "foo"
            });

            app.UseWebApi(config);

        }

        private static Task<ClaimsIdentity> AuthenticateBasicCredentials(BasicAuthenticationContext basicAuthenticationContext)
        {
            return Task.FromResult(new ClaimsIdentity(new[] { new Claim(ClaimTypes.NameIdentifier, "foo"), }, "Basic"));
        }
    }
}
