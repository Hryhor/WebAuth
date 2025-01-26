using System.Security.Claims;
using WebAuth.Models;
using WebAuth.Models.DTO;

namespace WebAuth.Interfaces.Auth
{
    public interface ITokenService
    {
        Tokens GenerateTokens(UserDTO user);
        string GenerateAccessToken(UserDTO user);
        string GenerateRefreshToken(UserDTO user);
        Task SaveToken(UserDTO user, string refreshToken);
        Task DeleteToken(string token);
        string ValidateAccessToken(string token);
        string ValidateRefreshToken(string token);
        ClaimsPrincipal? GetPrincipalFromExpiredToken(string token);
    }
}
