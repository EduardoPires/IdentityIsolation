namespace EP.IdentityIsolation.Infra.CrossCutting.Identity.Model
{
    public class UserLoginInfoViewModel
    {
        public string LoginProvider { get; set; }

        public string ProviderKey { get; set; }
    }
}