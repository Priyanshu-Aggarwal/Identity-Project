using AutoMapper;
using IdentityProject.Models;

namespace IdentityProject.Mappings
{
    public class UserMapping : Profile
    {
        public UserMapping() { 
            CreateMap<UserRegistrationDto,User>().ReverseMap();
        }
        
    }
}
