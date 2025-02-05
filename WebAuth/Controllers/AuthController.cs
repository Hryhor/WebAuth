using AutoMapper;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using System.Net;
using System.Security.Claims;
using WebAuth.Data;
using WebAuth.Interfaces.Auth;
using WebAuth.Models;
using WebAuth.Models.DTO;
using WebAuth.Repository.IRepository;
using WebAuth.Services;

namespace WebAuth.Controllers
{
    [Route("api/Auth")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        protected APIResponse _response;
        private readonly IAuthRepository _authRepository;
        private readonly ITokenService _tokenService;

        private readonly IMapper _mapper;
        private readonly ApplicationDbContext _db;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IEmailService _emailService;

        public AuthController(IAuthRepository authRepository, ITokenService tokenService,
            UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager,
            ApplicationDbContext db, IMapper mapper, IEmailService emailService
            )
        {
            _response = new();
            _authRepository = authRepository;
            _tokenService = tokenService;
            _db = db;
            _userManager = userManager;
            _roleManager = roleManager;
            _mapper = mapper;
            _emailService = emailService;
        }

        [HttpPost("register")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<IActionResult>Register([FromBody]RegisterRequestDTO requestDTO)
        {
            try
            {
                if (requestDTO == null)
                {
                    _response.StatusCode = HttpStatusCode.BadRequest;
                    _response.IsSuccess = false;
                    _response.ErrorMessages.Add("Username or password is incorrect");

                    return BadRequest(_response);
                }

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
                    _response.StatusCode = HttpStatusCode.BadRequest;
                    _response.IsSuccess = false; 
                    _response.ErrorMessages = new List<string>() { "User creation failed" };//result.Errors.Select(e => e.Description).ToList();

                    return BadRequest(_response);
                }

                if (createdUser)
                {
                    if (!await _authRepository.RoleExistsAsync("admin"))
                    {
                        await _authRepository.CreateRoleAsync("admin");
                        await _authRepository.CreateRoleAsync("customer");
                    }

                    await _authRepository.AddUserToRoleAsync(applicationUser, "admin"); //await _userManager.AddToRoleAsync(applicationUser, "admin");

                   
                    var userToReturn = _authRepository.GetUserByNameAsync(requestDTO.Name); //_db.ApplicationUsers.FirstOrDefault(u => u.UserName == requestDTO.Name);

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

                        var token = await _userManager.GenerateEmailConfirmationTokenAsync(applicationUser);
                        var confirmationLink = Url.Action("ConfirmEmail", "Auth", new { userId = applicationUser.Id, token = token }, Request.Scheme);

                        // Отправка email с подтверждением
                        await _emailService.SendEmailAsync(applicationUser.Email, "Подтверждение почты", $"Перейдите по следующей ссылке для подтверждения: {confirmationLink}");


                        //await ConfirmEmail(userCreated.Id, takenAccess);

                        Response.Cookies.Append("refreshToken", refreshToken, cookieOptions);

                        var resDTO = new
                        {
                            AccessToken = takenAccess,
                            //RefreshToken = refreshToken
                        };

                        _response.Result = resDTO;
                        _response.StatusCode = HttpStatusCode.OK;
                        _response.IsSuccess = true;

                        return Ok(_response);
                    }
                }

                _response.StatusCode = HttpStatusCode.BadRequest;
                _response.IsSuccess = false;
                _response.ErrorMessages.Add("Error occurred during user creation");
                return BadRequest(_response);
            } 
            catch (Exception ex)
            {
                _response.StatusCode = HttpStatusCode.BadRequest;
                _response.IsSuccess = false;
                _response.ErrorMessages = new List<string>() { ex.ToString() };
                return BadRequest(_response);
            }
        }


        [HttpPost("login")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<IActionResult> Login([FromBody]LoginRequestDTO requestDTO)
        {
            try
            {
                if (requestDTO == null)
                {
                    _response.IsSuccess = false;
                    _response.StatusCode = HttpStatusCode.BadRequest;
                    _response.ErrorMessages.Add("Data cannot be empty");

                    return BadRequest(_response);
                }

                string email = requestDTO.Email.ToUpper();

                var user = await _authRepository.GetUserByEmailAsync(email);  //_db.ApplicationUsers.FirstOrDefault(u => u.Email.ToUpper() == email);

                if (user == null)
                {
                    _response.IsSuccess = false;
                    _response.StatusCode = HttpStatusCode.BadRequest;
                    _response.ErrorMessages = new List<string>() { "This User does not exist" };
                    return BadRequest(_response);
                }

                bool isValid = await _userManager.CheckPasswordAsync(user, requestDTO.Password);

                if (isValid == false)
                {
                    _response.IsSuccess = false;
                    _response.StatusCode = HttpStatusCode.BadRequest;
                    _response.ErrorMessages = new List<string>() { "Your email or passwor does not valid" };

                    return BadRequest(_response);
                }

                var roles = await _userManager.GetRolesAsync(user);

                //сгенерить токены
                var userLogin = _mapper.Map<UserDTO>(user);
                var takenAccess = _tokenService.GenerateAccessToken(userLogin);
                var refreshToken = _tokenService.GenerateRefreshToken(userLogin);

                var cookieOptions = new CookieOptions
                {
                    HttpOnly = true, // Только для HTTP, не доступно через JavaScript
                    Secure = true,   // Использовать cookie только через HTTPS
                    MaxAge = TimeSpan.FromDays(30), // Срок действия cookie (30 дней)
                    SameSite = SameSiteMode.Strict // Защищает от CSRF атак
                };

                Response.Cookies.Append("refreshToken", refreshToken, cookieOptions);

                var resDTO = new
                {
                    AccessToken = takenAccess,
                    //RefreshToken = refreshToken
                };

                _response.Result = resDTO;
                _response.IsSuccess = true;
                _response.StatusCode = HttpStatusCode.OK;

                return Ok(_response);
            } catch(Exception ex)
            {
                _response.StatusCode = HttpStatusCode.BadRequest;
                _response.IsSuccess = false;
                _response.ErrorMessages = new List<string>() { ex.ToString() };
                return BadRequest(_response);
            }
        }

        [HttpPost("logout")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<IActionResult> Logout()
        {
            try
            {
                var refreshToken = Request.Cookies["refreshToken"];

                if (string.IsNullOrEmpty(refreshToken))
                {
                    Response.Cookies.Delete("refreshToken");
                    _response.IsSuccess = false;
                    _response.Result = "No refresh token found in cookies.";
                    _response.StatusCode = HttpStatusCode.BadRequest;
                    return BadRequest(_response);
                }

                var tokenEntity = await _authRepository.GetTokenAsync(refreshToken);

                if (tokenEntity == null)
                {
                    // Если токен не найден, удаляем куки и возвращаем ответ
                    Response.Cookies.Delete("refreshToken");
                    _response.IsSuccess = false;
                    _response.Result = "Invalid refresh token.";
                    _response.StatusCode = HttpStatusCode.NotFound;
                    return NotFound(_response);
                }

                await _authRepository.RemoveTokenAsync(tokenEntity);

                // Удаление куки
                Response.Cookies.Delete("refreshToken");

                _response.IsSuccess = true;
                _response.StatusCode = HttpStatusCode.OK;
                _response.Result = "Successfully logged out";

                return Ok(_response);
            }
            catch (Exception ex)
            {
                _response.IsSuccess = false;
                _response.ErrorMessages = new List<string>() { ex.ToString() };
                return BadRequest(_response);
            }
            
        }

        [HttpPost("refresh")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<IActionResult> Refresh(UserDTO userName)
        {
            try
            {
                var refreshToken = Request.Cookies["refreshToken"];

                if (string.IsNullOrEmpty(refreshToken))
                {
                    Response.Cookies.Delete("refreshToken");
                    _response.IsSuccess = false;
                    _response.Result = "No refresh token found in cookies.";
                    _response.StatusCode = HttpStatusCode.BadRequest;
                    return BadRequest(_response);
                }

                var userData = _tokenService.ValidateRefreshToken(refreshToken);
                var tokenFromDb = _authRepository.GetTokenAsync(refreshToken); //await _db.UserTokens.FirstOrDefaultAsync(e => e.Value == refreshToken);

                if (userData == null || tokenFromDb == null)
                {
                    _response.IsSuccess = false;
                    _response.ErrorMessages = new List<string>() { "Invalid token or token not found in the database" };
                    return BadRequest(_response);
                }

                var user = await _authRepository.GetUserByIdAsync(userName.Id); //await _db.Users.FirstOrDefaultAsync(u => u.Id == userName.Id);

                if (user == null)
                {
                    _response.IsSuccess = false;
                    _response.ErrorMessages = new List<string>() { "User not found" };
                    return BadRequest(_response);
                }

                //var tokens = _tokenService.GenerateTokens();
                var tokens = _tokenService.GenerateTokens(new UserDTO 
                { 
                    Id = user.Id.ToString(), 
                    Name = user.UserName 
                });

                _response.IsSuccess = true;
                _response.StatusCode = HttpStatusCode.OK;
                return Ok(_response);
            }
            catch (Exception ex)
            {
                _response.IsSuccess = false;
                _response.ErrorMessages = new List<string>() { ex.ToString() };
                return BadRequest(_response);
            }
        }

        [HttpGet("confirmemail")]
        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                _response.IsSuccess = false;
                _response.ErrorMessages.Add("Неверный пользователь.");
                return BadRequest(_response);
            }

            var result = await _userManager.ConfirmEmailAsync(user, token);
            if (result.Succeeded)
            {
                _response.IsSuccess = true;
                _response.Result = "Электронная почта успешно подтверждена.";
                return Ok(_response);
            }

            _response.IsSuccess = false;
            _response.ErrorMessages.Add("Ошибка подтверждения электронной почты.");
            return BadRequest(_response);
        }
    }
}
