using System.Security.Claims;
using System.Web.Http;

namespace BasicAuthentication.Sample.Controllers
{
    [Authorize]
    public class CustomerController : ApiController
    {
        public string Get()
        {
            var claim = (User as ClaimsPrincipal).FindFirst(ClaimTypes.NameIdentifier);

            return claim.Value;
        }
    }
}
