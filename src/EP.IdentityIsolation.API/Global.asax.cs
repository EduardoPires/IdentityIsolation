using System;
using System.Web;
using System.Web.Http;

namespace EP.IdentityIsolation.API
{
    public class Global : HttpApplication
    {
        protected void Application_Start(object sender, EventArgs e)
        {
            GlobalConfiguration.Configure(WebApiConfig.Register);
            GlobalConfiguration.Configure(DependencyInjector.Register);
        }
    }
}