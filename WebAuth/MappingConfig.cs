using AutoMapper;
using WebAuth.Models;
using WebAuth.Models.DTO;

namespace WebAuth
{
    public class MappingConfig : Profile
    {
        public MappingConfig()
        {
            CreateMap<ApplicationUser, UserDTO>().ReverseMap();
        }
    }
}
