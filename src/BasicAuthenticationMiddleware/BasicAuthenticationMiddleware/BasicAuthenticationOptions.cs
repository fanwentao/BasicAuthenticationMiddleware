using System;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Security;

namespace BasicAuthenticationMiddleware
{
    public class BasicAuthenticationOptions : AuthenticationOptions
    {
        public BasicAuthenticationOptions()
            : base(Constants.BasicAuthenticationType)
        {
            AuthenticationMode = AuthenticationMode.Active;
            AuthenticateBasicCredentials = context => null;
        }

        public string Realm { get; set; }
        public Func<BasicAuthenticationContext, Task<ClaimsIdentity>> AuthenticateBasicCredentials { get; set; }

    }
}
