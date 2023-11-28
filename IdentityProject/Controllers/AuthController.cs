using AutoMapper;
using IdentityProject.Models;
using IdentityProject.Services.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityProject.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IUserAuthenticationService _repository;
        private readonly IRegistrationService _registrationService;
        public AuthController(IServiceProvider serviceProvider) 
        {
            _repository = serviceProvider.GetRequiredService<IUserAuthenticationService>();
            _registrationService = serviceProvider.GetRequiredService<IRegistrationService>();
        }


        [Authorize(AuthenticationSchemes ="Bearer", Roles ="Admin")]
        [HttpGet("admin")]
        public async Task<IActionResult> AdminPage()
        {
            return Ok("This is an Admin Page");
        }

        [Authorize(AuthenticationSchemes ="Bearer", Roles ="User")]
        [HttpGet("user")]
        public async Task<IActionResult> UserPage()
        {
            return Ok("This is a User Page");
        }

        
        [HttpPost("login")]
        public async Task<IActionResult> Authenticate([FromBody] UserLoginDto user)
        {
           var result = await _repository.ValidateUserAsync(user);
            if (result)
            {
                return Ok(new { Token = await _repository.CreateTokenAsync() });
            }
            return Unauthorized();

        }

        [HttpPost("register")]
        public async Task<IActionResult> RegisterUser([FromBody] UserRegistrationDto userRegistration)
        {

            var userResult = await _registrationService.RegisterUserAsync(userRegistration);
            return !userResult.Succeeded ? new BadRequestObjectResult(userResult) : StatusCode(201);
        }

        [HttpGet("getName"), Authorize(AuthenticationSchemes ="Bearer")]
       
        public async Task<IActionResult> GetName()
        {
            var result =User.Claims.First(c=> c.Type == "FirstName-LastName");
            return Ok(result.ToString());
        }

        [HttpPost("lock")]
        public async Task<IActionResult> LockUser([FromQuery] string email)
        {
            return Ok(await _repository.LockUser(email));
        }

        [HttpPost("unlock")]
        public async Task<IActionResult> UnlockUser([FromQuery] string email)
        {
            return Ok(await _repository.UnLockUser(email));
        }
    }
}
