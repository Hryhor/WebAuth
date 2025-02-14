﻿namespace WebAuth.Models.DTO
{
    public class RegisterResponseDTO
    {
        public bool Success { get; set; }
        public string? Error { get; set; }
        public string? AccessToken { get; set; }
        public string? RefreshToken { get; set; }
        public ApplicationUser? applicationUser { get; set; }
    }
}
