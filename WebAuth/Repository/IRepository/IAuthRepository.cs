using WebAuth.Models.DTO;

namespace WebAuth.Repository.IRepository
{
    public interface IAuthRepository
    {
        Task<UserDTO> Register(RegisterRequestDTO registerRequestDTO);
        Task<UserDTO> Login(LoginRequestDTO loginRequestDTO);
    }
}
