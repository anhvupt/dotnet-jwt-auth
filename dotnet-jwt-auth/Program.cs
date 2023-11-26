using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(opt =>
    {
        opt.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = true,
            IssuerSigningKey =
                new SymmetricSecurityKey(Settings.GenerateSecretByte())
        };
    });
builder.Services.AddAuthorization();
builder.Services.AddSingleton<IAuthService, AuthService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

var summaries = new[]
{
    "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
};

app.MapPost("/login", (User userModel, IAuthService authService) =>
{
    var user = User.Repo.FirstOrDefault(x => x.UserName == userModel.UserName && x.Password == userModel.Password);
    if (user is null) return Results.NotFound(new { message = "Invalid" });

    var token = authService.GenerateToken(user);
    user.Password = string.Empty;
    return Results.Ok(new { user, token });
});

app.MapGet("/weatherforecast", () =>
    {
        var forecast = Enumerable.Range(1, 5).Select(index =>
                new WeatherForecast
                (
                    DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
                    Random.Shared.Next(-20, 55),
                    summaries[Random.Shared.Next(summaries.Length)]
                ))
            .ToArray();
        return forecast;
    })
    .WithName("GetWeatherForecast")
    .WithOpenApi();

app.MapPost("/weatherforecast", () => { return Results.NoContent(); }).RequireAuthorization();

app.Run();

internal record WeatherForecast(DateOnly Date, int TemperatureC, string? Summary)
{
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}

internal static class Settings
{
    internal static string SecretKey = new Guid().ToString();

    internal static byte[] GenerateSecretByte()
    {
        return Encoding.ASCII.GetBytes(SecretKey);
    }
}

internal interface IAuthService
{
    string GenerateToken(User user);
}

internal class AuthService : IAuthService
{
    public string GenerateToken(User user)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Settings.GenerateSecretByte();

        var token = tokenHandler.CreateToken(new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new Claim[]
            {
                new(ClaimTypes.Name, user.UserName),
                new(ClaimTypes.Role, user.Role is null ? "" : ((UserRole)user.Role).ToString())
            }),
            Expires = DateTime.UtcNow.AddDays(10),
            SigningCredentials =
                new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        });

        return tokenHandler.WriteToken(token);
    }
}

internal enum UserRole
{
    Admin
}

internal class User
{
    public static List<User> Repo = new()
        { new User { UserName = "user1", Email = "user1@email.com", Password = "123" } };

    public string UserName { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string? Email { get; set; } = string.Empty;
    public UserRole? Role { get; set; } = null;
}