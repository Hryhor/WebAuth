using AutoMapper;
using Microsoft.AspNetCore.Identity;
using WebAuth.Data;
using WebAuth.Models;
using WebAuth.Models.DTO;
using WebAuth.Repository.IRepository;

namespace WebAuth.Repository
{
    public class AuthRepository : IAuthRepository
    {
        private readonly ApplicationDbContext _db;
        private string secretKey;
        private readonly IMapper _mapper;

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

        public async Task<UserDTO> Register(RegisterRequestDTO registerRequestDTO)
        {
            ApplicationUser user = new()
            {
                Email = registerRequestDTO.Email,
                NormalizedEmail = registerRequestDTO.Email.ToUpper(),
                Name = registerRequestDTO.Name,
            };

            try
            {
                var result = await _userManager.CreateAsync(user, registerRequestDTO.Password); 

                if (result.Succeeded)
                {
                    if (!_roleManager.RoleExistsAsync("admin").GetAwaiter().GetResult())
                    {
                        await _roleManager.CreateAsync(new IdentityRole("admin"));
                        await _roleManager.CreateAsync(new IdentityRole("customer"));
                    }

                    await _userManager.AddToRoleAsync(user, "admin");
                    var userToReturn = _db.ApplicationUsers
                        .FirstOrDefault(u => u.UserName == registerRequestDTO.Name);

                    return _mapper.Map<UserDTO>(userToReturn);
                }

            }
            catch (Exception ex)
            {

            }

            return new UserDTO();
        }
        public async Task<UserDTO> Login(LoginRequestDTO loginRequestDTO)
        {
            return null;
        }
    }
}
