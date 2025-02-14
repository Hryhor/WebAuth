using Microsoft.AspNetCore.Authentication.BearerToken;

namespace WebAuth.Models.DTO
{
    public class LoginResponseDTO
    {
        public bool Success { get; set; }
        public string? Error { get; set; }
        public string? AccessToken { get; set; }
        public string? RefreshToken { get; set; }
    }
}
