using AutoMapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Net;
using WebAuth.Data;
using WebAuth.Interfaces.Auth;
using WebAuth.Models;
using WebAuth.Models.DTO;
using WebAuth.Repository.IRepository;
using WebAuth.Services;

namespace WebAuth.Repository
{
    public class AuthRepository : IAuthRepository
    {
        private readonly ApplicationDbContext _db;
        private string secretKey;

        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public AuthRepository(ApplicationDbContext db, IConfiguration configuration,
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager)
        {
            _db = db;
            secretKey = configuration.GetValue<string>("ApiSettings:Secret");
            _userManager = userManager;
            _roleManager = roleManager;
        }

        public bool IsUniqueUser(string email)
        {
            var user = _db.ApplicationUsers.FirstOrDefault(u => u.Email.ToUpper() == email);

            if (user == null)
            {
                return true;
            }

            return false;
        }

        public async Task<ApplicationUser?> GetUserByEmailAsync(string email)
        {
            var user = await _db.ApplicationUsers.FirstOrDefaultAsync(u => u.Email.ToUpper() == email);            

            if (user == null)
            {
                return null;
            }

            return user;
        }

        public async Task<ApplicationUser?> GetUserByNameAsync(string name)
        {
            var user = await _db.ApplicationUsers.FirstOrDefaultAsync(u => u.UserName == name);

            if (user == null)
            {
                return null;
            }

            return user;
        }

        public async Task<ApplicationUser?> GetUserByIdAsync(string id)
        {
            var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == id);

            if (user == null)
            {
                return null;
            }

            return user;
        }

        public async Task<bool> CreateUserAsync(ApplicationUser applicationUser, string password)
        {
            var result = await _userManager.CreateAsync(applicationUser, password);
            return result.Succeeded;
        }

        public async Task<bool> RoleExistsAsync(string roleName)
        {
            try
            {
                return await _roleManager.RoleExistsAsync(roleName);
            }
            catch (Exception ex)
            {
                return false;
            }
        }

        public async Task CreateRoleAsync(string roleName)
        {
            await _roleManager.CreateAsync(new IdentityRole(roleName));
        }

        public async Task AddUserToRoleAsync(ApplicationUser applicationUser, string roleName)
        {
            await _userManager.AddToRoleAsync(applicationUser, roleName);
        }
        
        public async Task RemoveTokenAsync(IdentityUserToken<string> tokenEntity)
        {
            _db.UserTokens.Remove(tokenEntity);
            await _db.SaveChangesAsync();
        }

        public async Task<IdentityUserToken<string>?> GetTokenAsync(string token)
        {
            var tokenFromDB = await _db.UserTokens.FirstOrDefaultAsync(e => e.Value == token);

            if (tokenFromDB == null) 
            {
                return null;
            }

            return tokenFromDB;
        }
    }
}
