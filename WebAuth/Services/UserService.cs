using AutoMapper;
using Microsoft.AspNetCore.Identity;
using WebAuth.Interfaces.Auth;
using WebAuth.Models;
using WebAuth.Models.DTO;
using WebAuth.Repository.IRepository;

namespace WebAuth.Services
{
    public class UserService : IUserService
    {
        protected APIResponse _response;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IPasswordService _passwordService;
        private readonly IAuthRepository _authRepository;
        private readonly IMapper _mapper;
        private readonly IEmailService _emailService;
        private readonly ITokenService _tokenService;


        public UserService(IPasswordService passwordService, IAuthRepository authRepository,
           UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager,
           IMapper mapper, IEmailService emailService, ITokenService tokenService)
        {
            _response = new();
            _userManager = userManager;
            _passwordService = passwordService;
            _authRepository = authRepository;
            _roleManager = roleManager;
            _mapper = mapper;
            _emailService = emailService;
            _tokenService = tokenService;
        }

        public async Task<RegisterResponseDTO> RegisterAsync(RegisterRequestDTO requestDTO)
        {
            try
            {
                var applicationUser = new ApplicationUser()
                {
                    Email = requestDTO.Email,
                    NormalizedEmail = requestDTO.Email.ToUpper(),
                    Name = requestDTO.Name,
                    UserName = requestDTO.Name,
                };

                var createdUser = await _authRepository.CreateUserAsync(applicationUser, requestDTO.Password); //await _userManager.CreateAsync(applicationUser, requestDTO.Password);

                if (!createdUser)
                {
                    return new RegisterResponseDTO()
                    {
                        Success = false,
                        Error = "User creation failed",
                        AccessToken = null,
                        RefreshToken = null,
                        applicationUser = null,
                    };
                }

                if (createdUser)
                {
                    if (!await _authRepository.RoleExistsAsync("admin"))
                    {
                        await _authRepository.CreateRoleAsync("admin");
                        await _authRepository.CreateRoleAsync("customer");
                    }

                    await _authRepository.AddUserToRoleAsync(applicationUser, "admin");

                    var userToReturn = await _authRepository.GetUserByNameAsync(requestDTO.Name);

                    if (userToReturn != null)
                    {
                        var userCreated = _mapper.Map<UserDTO>(userToReturn);
                        var takenAccess = _tokenService.GenerateAccessToken(userCreated);
                        var refreshToken = _tokenService.GenerateRefreshToken(userCreated);
                        await _tokenService.SaveToken(userCreated, refreshToken);

                        var cookieOptions = new CookieOptions
                        {
                            HttpOnly = true, // Только для HTTP, не доступно через JavaScript
                            Secure = true,   // Использовать cookie только через HTTPS
                            MaxAge = TimeSpan.FromDays(30), // Срок действия cookie (30 дней)
                            SameSite = SameSiteMode.Strict // Защищает от CSRF атак
                        };

                        return new RegisterResponseDTO()
                        {
                            Success = true,
                            Error = null,
                            AccessToken = takenAccess,
                            RefreshToken = refreshToken
                        };
                    }
                }

                return new RegisterResponseDTO()
                {
                    Success = false,
                    Error = "User creation failed",
                    AccessToken = null,
                    RefreshToken = null,
                    applicationUser = null,
                };
            }
            catch (Exception ex)
            {
                return new RegisterResponseDTO()
                {
                    Success = false,
                    Error = ex.Message,
                    AccessToken = null,
                    RefreshToken = null,
                };
            }
        }

        public async Task<LoginResponseDTO> LoginAsync(LoginRequestDTO requestDTO)
        {
            try
            {
                string email = requestDTO.Email.ToUpper();

                var user = await _authRepository.GetUserByEmailAsync(email);

                if (user == null)
                {
                    return new LoginResponseDTO()
                    {
                        Success = false,
                        Error = "This User does not exist",
                        AccessToken = null,
                        RefreshToken = null,
                    };
                }

                bool isValid = await _userManager.CheckPasswordAsync(user, requestDTO.Password);

                if (isValid == false)
                {
                    return new LoginResponseDTO()
                    {
                        Success = false,
                        Error = "Your email or passwor does not valid",
                        AccessToken = null,
                        RefreshToken = null,
                    };
                }

                var roles = await _userManager.GetRolesAsync(user);

                //сгенерить токены
                var userLogin = _mapper.Map<UserDTO>(user);
                var takenAccess = _tokenService.GenerateAccessToken(userLogin);
                var refreshToken = _tokenService.GenerateRefreshToken(userLogin);

                return new LoginResponseDTO()
                {
                    Success = true,
                    Error = null,
                    AccessToken = takenAccess,
                    RefreshToken = refreshToken,
                };
            }
            catch (Exception ex)
            {
                return new LoginResponseDTO()
                {
                    Success = false,
                    Error = ex.Message,
                    AccessToken = null,
                    RefreshToken = null,
                };
            }
        }

        public async Task<RefreshResponceDTO> RefreshAsync(string refreshToken, UserDTO userName)
        {
            if (string.IsNullOrEmpty(refreshToken))
            {
                return new RefreshResponceDTO
                {
                    Success = false,
                    Error = "No refresh token found in cookies.",
                };
            }

            var userData = _tokenService.ValidateRefreshToken(refreshToken);
            var tokenFromDb = _authRepository.GetTokenAsync(refreshToken);

            if (userData == null || tokenFromDb == null)
            {
                return new RefreshResponceDTO
                {
                    Success = false,
                    Error = "Invalid token or token not found in the database",
                    AccessToken = null,
                    RefreshToken = null
                };
            }

            var user = await _authRepository.GetUserByIdAsync(userName.Id);

            if (user == null)
            {
                return new RefreshResponceDTO
                {
                    Success = false,
                    Error = "User not found",
                    AccessToken = null,
                    RefreshToken = null
                };
            }

            var tokens = _tokenService.GenerateTokens(new UserDTO
            {
                Id = user.Id.ToString(),
                Name = user.UserName
            });

            return new RefreshResponceDTO
            {
                Success = true,
                Error = null,
                AccessToken = tokens.AccessToken,
                RefreshToken = tokens.RefreshToken
            };
        }

        public async Task<LogoutResponceDTO> LogoutAsync(string refreshToken)
        {
            if (string.IsNullOrEmpty(refreshToken))
            { 
                return new LogoutResponceDTO
                {
                    Success = false,
                    Error = "No refresh token found in cookies.",
                };
            }

            var tokenEntity = await _authRepository.GetTokenAsync(refreshToken);

            if (tokenEntity == null)
            {
                return new LogoutResponceDTO
                {
                    Success = false,
                    Error = "Invalid refresh token."
                };
            }

            await _authRepository.RemoveTokenAsync(tokenEntity);

            return new LogoutResponceDTO
            {
                Success = true,
                Error = null,
            };
        }

        public async Task<ConfirmEmailResponceDTO> ConfirmEmailAsync(string userId, string token)
        {
            var user = await _userManager.FindByIdAsync(userId);

            if (user == null)
            {
                return new ConfirmEmailResponceDTO
                {
                    Success = false,
                    Message = "Invalid user."
                };               
            }

            var result = await _userManager.ConfirmEmailAsync(user, token);

            if (!result.Succeeded)
            {
                return new ConfirmEmailResponceDTO
                {
                    Success = false,
                    Message = "Email confirmation error."
                };
            }

            return new ConfirmEmailResponceDTO
            {
                Success = true,
                Message = " The email has been successfully verified."
            };
           
        }
    }
}
