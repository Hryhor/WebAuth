using Microsoft.AspNetCore.Identity;

namespace WebAuth.Models
{
    public class ApplicationUser : IdentityUser
    {
        public string Name { get; set; }
    }
}
