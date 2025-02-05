using System.Net;
using WebAuth.Interfaces.Auth;
using WebAuth.Models;
using WebAuth.Models.DTO;
using WebAuth.Repository;
using WebAuth.Repository.IRepository;

namespace WebAuth.Services
{
    public class UserService
    {
        private readonly IPasswordService _passwordService;
        private readonly IAuthRepository _authRepository;

        public UserService(IPasswordService passwordService, IAuthRepository authRepository)
        {
           
            _passwordService = passwordService;
            _authRepository = authRepository;
        }
    }
}
