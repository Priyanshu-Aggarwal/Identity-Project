using Microsoft.AspNetCore.Identity;

namespace IdentityProject.Models
{
    public class User : IdentityUser
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }

        public static explicit operator User(UserRegistrationDto v)
        {
            throw new NotImplementedException();
        }
    }
}
