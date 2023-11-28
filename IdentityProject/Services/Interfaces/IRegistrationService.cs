using IdentityProject.Models;
using Microsoft.AspNetCore.Identity;

namespace IdentityProject.Services.Interfaces
{
    public interface IRegistrationService
    {
        Task<IdentityResult> RegisterUserAsync(UserRegistrationDto userForRegistration);
    }
}
