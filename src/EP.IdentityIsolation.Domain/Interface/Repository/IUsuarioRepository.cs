using System;
using System.Collections.Generic;
using EP.IdentityIsolation.Domain.Entities;

namespace EP.IdentityIsolation.Domain.Interface.Repository
{
    public interface IUsuarioRepository : IDisposable
    {
        Usuario ObterPorId(string id);
        IEnumerable<Usuario> ObterTodos();
    }
}