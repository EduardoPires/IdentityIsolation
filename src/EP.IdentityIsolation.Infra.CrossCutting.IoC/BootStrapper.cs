using EP.IdentityIsolation.Domain.Interface.Repository;
using EP.IdentityIsolation.Infra.CrossCutting.Identity.Configuration;
using EP.IdentityIsolation.Infra.CrossCutting.Identity.Context;
using EP.IdentityIsolation.Infra.CrossCutting.Identity.Model;
using EP.IdentityIsolation.Infra.Data.Repository;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.Owin.Security;
using SimpleInjector;

namespace EP.IdentityIsolation.Infra.CrossCutting.IoC
{
    public class BootStrapper
    {
        public static void RegisterServices(Container container)
        {
            container.RegisterPerWebRequest<ApplicationDbContext>();
            container.RegisterPerWebRequest<IUserStore<ApplicationUser>>(() => new UserStore<ApplicationUser>(new ApplicationDbContext()));
            container.RegisterPerWebRequest<IRoleStore<IdentityRole, string>>(() => new RoleStore<IdentityRole>());
            container.RegisterPerWebRequest<ApplicationRoleManager>();
            container.RegisterPerWebRequest<ApplicationUserManager>();
            container.RegisterPerWebRequest<ApplicationSignInManager>();
            container.RegisterPerWebRequest<ISecureDataFormat<AuthenticationTicket>>(() => new FakeTicket());
            
            container.RegisterPerWebRequest<IUsuarioRepository, UsuarioRepository>();
        } 
    }
}