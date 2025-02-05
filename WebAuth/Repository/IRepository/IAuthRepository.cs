using Microsoft.AspNetCore.Identity;
using WebAuth.Models;
using WebAuth.Models.DTO;

namespace WebAuth.Repository.IRepository
{
    public interface IAuthRepository
    {
        //Task<UserDTO> Register(RegisterRequestDTO registerRequestDTO);
        //Task<UserDTO> Login(LoginRequestDTO loginRequestDTO);
        bool IsUniqueUser(string email);
        Task<ApplicationUser?> GetUserByEmailAsync(string email);
        Task<ApplicationUser?> GetUserByNameAsync(string name);
        Task<ApplicationUser?> GetUserByIdAsync(string id);
        Task<bool> CreateUserAsync(ApplicationUser applicationUser, string password);
        Task<bool> RoleExistsAsync(string roleName);
        Task CreateRoleAsync(string roleName);
        Task AddUserToRoleAsync(ApplicationUser applicationUser, string roleName);
        Task RemoveTokenAsync(IdentityUserToken<string> tokenEntity);
        Task<IdentityUserToken<string>?> GetTokenAsync(string token);
    }
}
