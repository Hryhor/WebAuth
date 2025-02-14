using Microsoft.AspNetCore.Mvc;
using WebAuth.Models.DTO;

namespace WebAuth.Interfaces.Auth
{
    public interface IUserService
    {
        Task<RegisterResponseDTO> RegisterAsync(RegisterRequestDTO requestDTO);
        Task<LoginResponseDTO> LoginAsync(LoginRequestDTO requestDTO);
        Task<LogoutResponceDTO> LogoutAsync(string refreshToken);
        Task<RefreshResponceDTO> RefreshAsync(string refreshToken, UserDTO userName);
        Task<ConfirmEmailResponceDTO> ConfirmEmailAsync(string userId, string token);
    }
}
