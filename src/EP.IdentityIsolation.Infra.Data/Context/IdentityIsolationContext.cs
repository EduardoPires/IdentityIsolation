using System.Data.Entity;
using EP.IdentityIsolation.Domain.Entities;
using EP.IdentityIsolation.Infra.Data.EntityConfig;

namespace EP.IdentityIsolation.Infra.Data.Context
{
    public class IdentityIsolationContext : DbContext
    {
        public IdentityIsolationContext()
            : base("DefaultConnection")
        {
            
        }

        public DbSet<Usuario> Usuarios { get; set; }

        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            modelBuilder.Configurations.Add(new UsuarioConfig());

            base.OnModelCreating(modelBuilder);
        }
    }
}