using AutoMapper;
using IdentityProject.Models;
using IdentityProject.Services.Interfaces;
using Microsoft.AspNetCore.Identity;

namespace IdentityProject.Services.Implementations
{
    public class RegistrationService : IRegistrationService
    {
        private readonly UserManager<User> _userManager;
        private readonly IMapper _mapper;
        public RegistrationService(IServiceProvider serviceProvider, IMapper mapper)
        {
            _userManager = serviceProvider.GetRequiredService<UserManager<User>>();
            _mapper = mapper;
        }
        public async Task<IdentityResult> RegisterUserAsync(UserRegistrationDto userRegistration)
        {
            var user = _mapper.Map<User>(userRegistration);
            var result = await _userManager.CreateAsync(user, userRegistration.Password);                 
            return result;
        }
    }
}
