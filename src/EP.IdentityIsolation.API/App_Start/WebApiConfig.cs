using System.Web.Http;
using System.Web.Http.Cors;
using EP.IdentityIsolation.API.Filters;
using Microsoft.Owin.Security.OAuth;

namespace EP.IdentityIsolation.API
{
    public static class WebApiConfig
    {
        public static void Register(HttpConfiguration config)
        {
            // Web API configuration and services
            // Configure Web API to use only bearer token authentication.
            config.SuppressDefaultHostAuthentication();
            config.Filters.Add(new HostAuthenticationFilter(OAuthDefaults.AuthenticationType));

            // Web API routes
            config.MapHttpAttributeRoutes();

            // CORS config
            var cors = new EnableCorsAttribute("*", "*", "get,post");
            config.EnableCors(cors);

            config.Routes.MapHttpRoute(
                name: "DefaultApi",
                routeTemplate: "api/{controller}/{id}",
                defaults: new { id = RouteParameter.Optional }
            );

            // Enforce HTTPS
            config.Filters.Add(new RequireHttpsAttribute());
        }
    }
}
