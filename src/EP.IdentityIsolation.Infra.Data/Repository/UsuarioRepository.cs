using System;
using System.Collections.Generic;
using System.Linq;
using EP.IdentityIsolation.Domain.Entities;
using EP.IdentityIsolation.Domain.Interface.Repository;
using EP.IdentityIsolation.Infra.Data.Context;

namespace EP.IdentityIsolation.Infra.Data.Repository
{
    public class UsuarioRepository : IUsuarioRepository
    {
        private readonly IdentityIsolationContext _db;

        public UsuarioRepository()
        {
            _db = new IdentityIsolationContext();
        }

        public Usuario ObterPorId(string id)
        {
            return _db.Usuarios.Find(id);
        }

        public IEnumerable<Usuario> ObterTodos()
        {
            return _db.Usuarios.ToList();
        }

        public void Dispose()
        {
            _db.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}