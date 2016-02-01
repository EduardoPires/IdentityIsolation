namespace EP.IdentityIsolation.Infra.CrossCutting.Identity.Model
{
    public class RemoveLoginViewModel
    {
        public string LoginProvider { get; set; }
        public string ProviderKey { get; set; }
    }
}