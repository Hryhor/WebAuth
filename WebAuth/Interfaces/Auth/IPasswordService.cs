namespace WebAuth.Interfaces.Auth
{
    public interface IPasswordService
    {
        string Generate(string password);
        bool Verify(string password, string hashedPassword);
    }
}
