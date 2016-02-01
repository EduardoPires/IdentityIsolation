namespace EP.IdentityIsolation.Infra.CrossCutting.Identity.Model
{
    public class UserInfoViewModel
    {
        public string Email { get; set; }

        public bool HasRegistered { get; set; }

        public string LoginProvider { get; set; }
    }
}