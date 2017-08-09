using System;
using System.Net;
using System.Net.Http;
using System.Web.Http.Controllers;
using System.Web.Http.Filters;

namespace EP.IdentityIsolation.API.Filters
{
    public class RequireHttpsAttribute : AuthorizationFilterAttribute
    {
        public int Port { get; set; }

        public RequireHttpsAttribute()
        {
            Port = 443;
        }

        public override void OnAuthorization(HttpActionContext actionContext)
        {
            var request = actionContext.Request;

            if (request.RequestUri.Scheme != Uri.UriSchemeHttps)
            {
                actionContext.Response = new HttpResponseMessage();
                var response = actionContext.Response;

                if (request.Method == HttpMethod.Get || request.Method == HttpMethod.Head)
                {
                    var uri = new UriBuilder(request.RequestUri)
                    {
                        Scheme = Uri.UriSchemeHttps,
                        Port = this.Port
                    };

                    response.StatusCode = HttpStatusCode.Found;
                    response.Headers.Location = uri.Uri;
                }
                else
                {
                    response.StatusCode = HttpStatusCode.Forbidden;
                }
            }
            else
            {
                base.OnAuthorization(actionContext);
            }
        }
    }
}