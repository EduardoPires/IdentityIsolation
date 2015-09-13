using System.Collections.Generic;

namespace EP.IdentityIsolation.Infra.CrossCutting.Identity.Model
{
    public class ConfigureTwoFactorViewModel
    {
        public string SelectedProvider { get; set; }
        public ICollection<string> Providers { get; set; }
    }
}