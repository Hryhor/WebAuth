using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
using System.Net;
using WebAuth.Interfaces.Auth;
using WebAuth.Models;
using WebAuth.Models.DTO;

namespace WebAuth.Controllers
{
    [Route("api/Auth")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        protected APIResponse _response;

        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IEmailService _emailService;
        private readonly IUserService _userService;

        public AuthController(UserManager<ApplicationUser> userManager,
             IEmailService emailService, IUserService userService)
        {
            _response = new();
            _userManager = userManager;
            _emailService = emailService;
            _userService = userService;
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

                if (!new EmailAddressAttribute().IsValid(requestDTO.Email))
                {
                    _response.StatusCode = HttpStatusCode.BadRequest;
                    _response.IsSuccess = false;
                    _response.ErrorMessages = new List<string> { "Invalid email format" };
                    
                    return BadRequest(_response);
                }

                var registerResult = await _userService.RegisterAsync(requestDTO);

                if (registerResult.Success == false)
                {
                    _response.StatusCode = HttpStatusCode.BadRequest;
                    _response.IsSuccess = false; 
                    _response.ErrorMessages = new List<string>() { registerResult.Error };

                    return BadRequest(_response);
                }

                var token = await _userManager.GenerateEmailConfirmationTokenAsync(registerResult.applicationUser);
                var confirmationLink = Url.Action("ConfirmEmail", "Auth", new { userId = registerResult.applicationUser.Id, token = token }, Request.Scheme);

                var cookieOptions = new CookieOptions
                {
                    HttpOnly = true, // Только для HTTP, не доступно через JavaScript
                    Secure = true,   // Использовать cookie только через HTTPS
                    MaxAge = TimeSpan.FromDays(30), // Срок действия cookie (30 дней)
                    SameSite = SameSiteMode.Strict // Защищает от CSRF атак
                };

                Response.Cookies.Append("refreshToken", registerResult.RefreshToken, cookieOptions);
                await _emailService.SendEmailAsync(registerResult.applicationUser.Email, "Подтверждение почты", $"Перейдите по следующей ссылке для подтверждения: {confirmationLink}");

                _response.Result = new List<string> {
                    registerResult.AccessToken,
                    registerResult.RefreshToken,
                };
                _response.StatusCode = HttpStatusCode.OK;
                _response.IsSuccess = true;
                return Ok(_response);
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

                var registerResult = await _userService.LoginAsync(requestDTO);

                if (registerResult.Success == false)
                {
                    _response.IsSuccess = false;
                    _response.StatusCode = HttpStatusCode.BadRequest;
                    _response.ErrorMessages = new List<string>() { registerResult.Error };
                    return BadRequest(_response);
                }

                var cookieOptions = new CookieOptions
                {
                    HttpOnly = true, // Только для HTTP, не доступно через JavaScript
                    Secure = true,   // Использовать cookie только через HTTPS
                    MaxAge = TimeSpan.FromDays(30), // Срок действия cookie (30 дней)
                    SameSite = SameSiteMode.Strict // Защищает от CSRF атак
                };

                Response.Cookies.Append("refreshToken", registerResult.RefreshToken, cookieOptions);

                _response.Result = new List<string>() {
                    registerResult.AccessToken,
                    registerResult.RefreshToken,
                };
                _response.IsSuccess = true;
                _response.StatusCode = HttpStatusCode.OK;

                return Ok(_response);
            } 
            catch(Exception ex)
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

                var logoutResult = await _userService.LogoutAsync(refreshToken);

                if (logoutResult.Success == false)
                {
                    Response.Cookies.Delete("refreshToken");
                    _response.IsSuccess = logoutResult.Success;
                    _response.Result = "Failed to log out.";
                    _response.StatusCode = HttpStatusCode.BadRequest;
                    return BadRequest(_response);
                }

                Response.Cookies.Delete("refreshToken");

                _response.IsSuccess = logoutResult.Success;
                _response.StatusCode = HttpStatusCode.OK;
                _response.Result = "Successfully logged out.";

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

                var refreshResult = await _userService.RefreshAsync(refreshToken, userName);

                if (refreshResult.Success == false)
                {
                    _response.IsSuccess = refreshResult.Success;
                    _response.Result = refreshResult.Error;
                    _response.StatusCode = HttpStatusCode.BadRequest;
                    return BadRequest(_response);
                }

                _response.IsSuccess = true;
                _response.Result = new List<string>() {
                    refreshResult.RefreshToken,
                    refreshResult.AccessToken,
                };
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
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            var resultConfirmedEmail = await _userService.ConfirmEmailAsync(userId, token);

            if (resultConfirmedEmail.Success == false)
            {
                _response.IsSuccess = resultConfirmedEmail.Success;
                _response.ErrorMessages = new List<string> { resultConfirmedEmail.Message };
                return BadRequest(_response);
            }

            _response.IsSuccess = true;
            _response.Result = resultConfirmedEmail.Message;
            return Ok(_response);
        }
    }
}
