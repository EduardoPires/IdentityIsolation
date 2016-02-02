using System.Web;
using System.Web.Http;
using EP.IdentityIsolation.Infra.CrossCutting.IoC;
using Microsoft.Owin;
using SimpleInjector;
using SimpleInjector.Advanced;
using SimpleInjector.Integration.WebApi;

namespace EP.IdentityIsolation.API
{
    public static class DependencyInjector
    {
        public static void Register(HttpConfiguration config)
        {
            using (var container = new Container())
            {
                container.Options.DefaultScopedLifestyle = new WebApiRequestLifestyle();

                // Chamada dos módulos do Simple Injector
                BootStrapper.RegisterServices(container);

                // Necessário para registrar o ambiente do Owin que é dependência do Identity
                // Feito fora da camada de IoC para não levar o System.Web para fora
                container.RegisterPerWebRequest(() =>
                {
                    if (HttpContext.Current != null && HttpContext.Current.Items["owin.Environment"] == null && container.IsVerifying())
                    {
                        return new OwinContext().Authentication;
                    }
                    return HttpContext.Current.GetOwinContext().Authentication;

                });

                // This is an extension method from the integration package.
                container.RegisterWebApiControllers(config);

                container.Verify();

                GlobalConfiguration.Configuration.DependencyResolver =
                    new SimpleInjectorWebApiDependencyResolver(container);
            }
        }
    }
}