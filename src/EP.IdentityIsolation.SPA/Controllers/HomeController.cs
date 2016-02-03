using System.Web.Mvc;

namespace EP.IdentityIsolation.SPA.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            ViewBag.Title = "Home Page";

            return View();
        }
    }
}