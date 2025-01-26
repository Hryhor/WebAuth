using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using WebAuth.Data;
using System.Security.Claims;
using System.Data;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json.Linq;
using WebAuth.Models;
using WebAuth.Interfaces.Auth;
using WebAuth.Models.DTO;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;

namespace WebAuth.Services
{
    public class TokenService : ITokenService
    {
        private readonly ApplicationDbContext _db;
        private string _secretKey;
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }

        public TokenService(IConfiguration configuration, ApplicationDbContext db)
        {
            _secretKey = configuration["ApiSettings:Secret"];
            _db = db;
        }

        public Tokens GenerateTokens(UserDTO user)
        {
            var accessToken = this.GenerateAccessToken(user);
            var refreshToken = this.GenerateRefreshToken(user);

            return new Tokens
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken
            };
        }

        public string GenerateAccessToken(UserDTO user)
        {

            if (user == null || user.Name == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Name)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secretKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(30), // Задайте время жизни токена
                SigningCredentials = creds
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(token);
        }

        public string GenerateRefreshToken(UserDTO user)
        {
            /*var randomBytes = new byte[64];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(randomBytes);
                return Convert.ToBase64String(randomBytes);
            }*/
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secretKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddDays(7), // Refresh токены обычно живут дольше
                SigningCredentials = creds
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(token);
        }

        public string ValidateAccessToken(string token)
        {
            try
            {
                var tokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secretKey))
                };

                var tokenHandler = new JwtSecurityTokenHandler();
                var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken validatedToken);

                if (validatedToken is JwtSecurityToken jwtToken &&
                    jwtToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                {
                    // Извлекаем имя пользователя из ClaimsPrincipal
                    var userName = principal.Identity?.Name; // Это основное имя (Name)
                    return userName; // Возвращаем имя пользователя
                }
                else
                {
                    throw new SecurityTokenException("Invalid token");
                }
            } catch (Exception ex)
            {
                return null;
            }
        }

        public string ValidateRefreshToken(string token)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.UTF8.GetBytes(_secretKey);

                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = false
                };

                var principal = tokenHandler.ValidateToken(token, validationParameters, out _);

                // Извлекаем userId из claims
                var userId = principal.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;
                return userId;
            }
            catch
            {
                throw new SecurityTokenException("Invalid token");
            }
        }

        public async Task SaveToken(UserDTO user, string refreshToken)
        {
            var userToken = new IdentityUserToken<string>
            {
                UserId = user.Id,
                LoginProvider = "MyApp",  
                Name = "RefreshToken",    
                Value = refreshToken  
            };

            var existingToken = await _db.UserTokens.FirstOrDefaultAsync(t => t.UserId == user.Id && t.Name == "RefreshToken");

            if (existingToken != null)
            {
                existingToken.Value = refreshToken; // Обновляем токен
                _db.UserTokens.Update(existingToken);
            }
            else
            {
                await _db.UserTokens.AddAsync(userToken); // Добавляем новый токен
            }

            await _db.SaveChangesAsync();
        }

        public async Task DeleteToken(string token)
        {
            var refreshToken = await _db.UserTokens.FirstOrDefaultAsync(e => e.Value == token);
            if (refreshToken != null)
            {
                _db.UserTokens.Remove(refreshToken);
                await _db.SaveChangesAsync();
            }
        }

        public ClaimsPrincipal? GetPrincipalFromExpiredToken(string token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secretKey)),
                ValidateLifetime = false
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;

            if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Invalid token");

            return principal;
        }
    }
}
