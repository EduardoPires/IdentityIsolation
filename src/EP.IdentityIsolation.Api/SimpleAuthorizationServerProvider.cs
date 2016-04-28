using EP.IdentityIsolation.Infra.CrossCutting.Identity.Configuration;
using Microsoft.Owin.Security.OAuth;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;

namespace EP.IdentityIsolation.Api
{
    internal class SimpleAuthorizationServerProvider : OAuthAuthorizationServerProvider
    {
        private ApplicationSignInManager _userService;

        public SimpleAuthorizationServerProvider(ApplicationSignInManager userService)
        {
            this._userService = userService;
        }

        public override async Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            context.Validated();
        }

        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { "*" });

            var user = await _userService.PasswordSignInAsync(context.UserName, context.Password, false, false);
            if (user == Microsoft.AspNet.Identity.Owin.SignInStatus.Failure)
            {
                context.SetError("invalid_grant", "Usuário ou senha inválidos");
                return;
            }

            var identity = new ClaimsIdentity(context.Options.AuthenticationType);

            identity.AddClaim(new Claim(ClaimTypes.Name, context.UserName));

            GenericPrincipal principal = new GenericPrincipal(identity, new string[] { });
            Thread.CurrentPrincipal = principal;

            context.Validated(identity);
        }
    }
}