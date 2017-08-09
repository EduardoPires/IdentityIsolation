using System.Web.Http;

namespace EP.IdentityIsolation.API.Controllers
{
    [Authorize]
    [RoutePrefix("api/values")]
    public class ValuesController : ApiController
    {
        // GET api/values
        public string Get()
        {
            var userName = this.RequestContext.Principal.Identity.Name;
            return $"Hello, {userName}.";
        }
    }
}
