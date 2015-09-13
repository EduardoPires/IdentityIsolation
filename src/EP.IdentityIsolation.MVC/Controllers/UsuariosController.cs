using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using EP.IdentityIsolation.Domain.Interface.Repository;

namespace EP.IdentityIsolation.MVC.Controllers
{
    public class UsuariosController : Controller
    {
        private readonly IUsuarioRepository _usuarioRepository;

        public UsuariosController(IUsuarioRepository usuarioRepository)
        {
            _usuarioRepository = usuarioRepository;
        }

        // GET: Usuarios
        public ActionResult Index()
        {
            return View(_usuarioRepository.ObterTodos());
        }

        // GET: Usuarios/Details/5
        public ActionResult Details(string id)
        {
            return View(_usuarioRepository.ObterPorId(id));
        }
    }
}
