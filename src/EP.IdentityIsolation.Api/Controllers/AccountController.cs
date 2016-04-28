using EP.IdentityIsolation.Domain.Interface.Repository;
using EP.IdentityIsolation.Infra.CrossCutting.Identity.Configuration;
using EP.IdentityIsolation.Infra.CrossCutting.Identity.Model;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web.Http;

namespace EP.IdentityIsolation.Api.Controllers
{

    public class AccountController : ApiController
    {

        private readonly ApplicationUserManager _userManager;
        public AccountController(ApplicationUserManager userManager)
        {
            _userManager = userManager;
        }

        [HttpPost]
        [Route("api/users")]
        public async Task<HttpResponseMessage> Post([FromBody] dynamic body)
        {
            var user = new ApplicationUser { UserName = (string)body.email, Email = (string)body.email };
            var result = await _userManager.CreateAsync(user, (string)body.password);

            if (result.Succeeded)
                return Request.CreateResponse(HttpStatusCode.Created, user);
            else
                return Request.CreateResponse(HttpStatusCode.BadRequest, result.Errors);
        }
    }
}