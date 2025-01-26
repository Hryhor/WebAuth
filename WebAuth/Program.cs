using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Serilog;
using WebAuth.Data;
using WebAuth.Models;
using WebAuth.Repository.IRepository;
using WebAuth.Repository;
using WebAuth.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using System.Text;
using WebAuth.Interfaces.Auth;
using WebAuth;


var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
Log.Logger = new LoggerConfiguration().MinimumLevel.Debug()
    .WriteTo.File("log/ShemaElemenLOG.txt", rollingInterval: RollingInterval.Day).CreateLogger();
builder.Services.AddControllers();
builder.Host.UseSerilog();


// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddIdentity<ApplicationUser, IdentityRole>().AddEntityFrameworkStores<ApplicationDbContext>().AddDefaultTokenProviders();

builder.Services.AddDbContext<ApplicationDbContext>(option =>
{
    option.UseNpgsql(builder.Configuration.GetConnectionString("DefaultSQLConnection"));
});

builder.Services.AddAutoMapper(typeof(MappingConfig));

var key = builder.Configuration["ApiSettings:Secret"];

builder.Services.AddAuthentication(option =>
{
    option.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    option.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;

}).AddJwtBearer(option =>
{
    option.RequireHttpsMetadata = false;
    option.SaveToken = true;
    option.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(key)),
        ValidateIssuer = false,
        ValidateAudience = false,
    };
});


builder.Services.AddScoped<ITokenService, TokenService>();
builder.Services.AddScoped<IAuthRepository, AuthRepository>();
builder.Services.AddScoped<IEmailService, EmailService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();


app.UseAuthorization();

app.MapControllers();

app.Run();

