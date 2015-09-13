using System.ComponentModel.DataAnnotations;

namespace EP.IdentityIsolation.Infra.CrossCutting.Identity.Model
{
    public class ForgotPasswordViewModel
    {
        [Required]
        [EmailAddress]
        [Display(Name = "Email")]
        public string Email { get; set; }
    }
}
