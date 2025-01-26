using WebAuth.Interfaces.Auth;

namespace WebAuth.Services
{
    public class PasswordService : IPasswordService
    {
        public string Generate(string password) => BCrypt.Net.BCrypt.EnhancedHashPassword(password);

        public bool Verify(string password, string hashedPassword) => BCrypt.Net.BCrypt.EnhancedVerify(password, hashedPassword);
    }
}
