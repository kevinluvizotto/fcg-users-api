using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Security.Claims;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using FCG.Users.Infrastructure;
using FCG.Users.Domain.Entities;

namespace FCG.Users.Api
{
    public enum UserRole
    {
        Admin,
        User
    }

    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // 🪵 Logging
            builder.Services.AddLogging(logging =>
            {
                logging.AddConsole();
                logging.SetMinimumLevel(LogLevel.Debug);
            });

            // 💾 Banco de Dados
            var connectionString = builder.Configuration["ConnectionStrings:FCGDatabase"]
                ?? throw new InvalidOperationException("Connection string 'FCGDatabase' não está configurada.");

            builder.Services.AddDbContext<UsersDbContext>(options =>
                options.UseSqlServer(connectionString));

            // 🔐 JWT
            var jwtKey = builder.Configuration["Jwt:Key"];
            if (string.IsNullOrEmpty(jwtKey))
                throw new InvalidOperationException("JWT Key não está configurada no appsettings.json.");

            builder.Services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = builder.Configuration["Jwt:Issuer"],
                    ValidAudience = builder.Configuration["Jwt:Audience"],
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
                    ClockSkew = TimeSpan.Zero
                };
            });

            // 🛡️ Autorização
            builder.Services.AddAuthorization(options =>
            {
                options.AddPolicy("AdminOnly", policy => policy.RequireRole(UserRole.Admin.ToString()));
                options.AddPolicy("UserOrAdmin", policy => policy.RequireRole(UserRole.Admin.ToString(), UserRole.User.ToString()));
            });

            // 📘 Swagger
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen(c =>
            {
                c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    In = ParameterLocation.Header,
                    Description = "Insira o token JWT (sem 'Bearer ').",
                    Name = "Authorization",
                    Type = SecuritySchemeType.Http,
                    Scheme = "bearer",
                    BearerFormat = "JWT"
                });

                c.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference
                            {
                                Type = ReferenceType.SecurityScheme,
                                Id = "Bearer"
                            }
                        },
                        Array.Empty<string>()
                    }
                });
            });

            var app = builder.Build();

            app.UseSwagger();
            app.UseSwaggerUI();
            app.UseAuthentication();
            app.UseAuthorization();

            // 🌡️ Health Check
            app.MapGet("/health", () => "OK");

            // 👥 USERS CRUD (Admin Only)
            app.MapGet("/users", async (UsersDbContext db) =>
            {
                var users = await db.Users.ToListAsync();
                return users.Any() ? Results.Ok(users) : Results.Ok(new List<User>());
            }).RequireAuthorization("AdminOnly");

            app.MapPost("/users", async (User user, UsersDbContext db) =>
            {
                if (await db.Users.AnyAsync(u => u.Email == user.Email))
                    return Results.BadRequest("Email já cadastrado.");

                user.Id = Guid.NewGuid();
                db.Users.Add(user);
                await db.SaveChangesAsync();
                return Results.Created($"/users/{user.Id}", user);
            }).RequireAuthorization("AdminOnly");

            // 🔑 LOGIN
            app.MapPost("/login", async (UserLogin login, UsersDbContext db, IConfiguration config) =>
            {
                var user = await db.Users.FirstOrDefaultAsync(u => u.Email == login.Email && u.PasswordHash == login.PasswordHash);
                if (user == null) return Results.Unauthorized();

                var token = GenerateJwtToken(user, config);
                return Results.Ok(new { token });
            });

            // 🆕 REGISTRO
            app.MapPost("/register", async (UserRegister newUser, UsersDbContext db) =>
            {
                if (await db.Users.AnyAsync(u => u.Email == newUser.Email))
                    return Results.BadRequest(new { message = "E-mail já cadastrado." });

                var user = new User
                {
                    Id = Guid.NewGuid(),
                    Name = newUser.Name,
                    Email = newUser.Email,
                    PasswordHash = newUser.PasswordHash,
                    Role = UserRole.User.ToString()
                };

                db.Users.Add(user);
                await db.SaveChangesAsync();

                return Results.Created($"/users/{user.Id}", new { user.Id, user.Name, user.Email });
            });

            // 🧩 PERFIL AUTENTICADO
            app.MapGet("/me", [Authorize] async (HttpContext http, UsersDbContext db) =>
            {
                var userId = http.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                if (string.IsNullOrEmpty(userId))
                    return Results.Json(new { message = "Token inválido." }, statusCode: 401);

                var user = await db.Users.FindAsync(Guid.Parse(userId));
                if (user == null)
                    return Results.NotFound(new { message = "Usuário não encontrado." });

                return Results.Ok(new { user.Id, user.Name, user.Email, user.Role });
            }).RequireAuthorization();

            // 🔒 ALTERAR SENHA
            app.MapPut("/me/password", [Authorize] async (HttpContext http, UsersDbContext db, ChangePasswordRequest req) =>
            {
                var userId = http.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                if (string.IsNullOrEmpty(userId))
                    return Results.Json(new { message = "Token inválido." }, statusCode: 401);

                var user = await db.Users.FindAsync(Guid.Parse(userId));
                if (user == null)
                    return Results.NotFound(new { message = "Usuário não encontrado." });

                if (user.PasswordHash != req.CurrentPassword)
                    return Results.BadRequest(new { message = "Senha atual incorreta." });

                user.PasswordHash = req.NewPassword;
                await db.SaveChangesAsync();

                return Results.Ok(new { message = "Senha alterada com sucesso." });
            }).RequireAuthorization();

            // 🎮 --- NOVO: Biblioteca local (UserGames) ---
            app.MapGet("/users/me/games", [Authorize] async (HttpContext http, UsersDbContext db) =>
            {
                var userIdStr = http.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                if (string.IsNullOrEmpty(userIdStr))
                    return Results.Json(new { message = "Token inválido." }, statusCode: 401);

                var userId = Guid.Parse(userIdStr);

                var games = await db.UserGames
                    .Where(ug => ug.UserId == userId)
                    .Select(ug => new { ug.GameId })
                    .ToListAsync();

                return Results.Ok(games);
            })
            .WithTags("Biblioteca");

            app.MapPost("/users/me/games", [Authorize] async (HttpContext http, UsersDbContext db) =>
            {
                var userIdStr = http.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                var gameIdStr = http.Request.Query["gameId"].ToString();

                if (string.IsNullOrEmpty(userIdStr) || string.IsNullOrEmpty(gameIdStr))
                    return Results.BadRequest(new { message = "Token ou gameId ausente." });

                if (!Guid.TryParse(gameIdStr, out var gameId))
                    return Results.BadRequest(new { message = "gameId inválido." });

                var userId = Guid.Parse(userIdStr);

                var alreadyOwned = await db.UserGames.AnyAsync(ug => ug.UserId == userId && ug.GameId == gameId);
                if (alreadyOwned)
                    return Results.BadRequest(new { message = "Jogo já adquirido." });

                db.UserGames.Add(new UserGame { UserId = userId, GameId = gameId });
                await db.SaveChangesAsync();

                return Results.Ok(new { message = "Jogo adicionado à biblioteca." });
            })
            .WithTags("Biblioteca");

            app.MapDelete("/users/me/games/{gameId}", [Authorize] async (HttpContext http, Guid gameId, UsersDbContext db) =>
            {
                var userIdStr = http.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                if (string.IsNullOrEmpty(userIdStr))
                    return Results.Json(new { message = "Token inválido." }, statusCode: 401);

                var userId = Guid.Parse(userIdStr);
                var userGame = await db.UserGames.FirstOrDefaultAsync(ug => ug.UserId == userId && ug.GameId == gameId);

                if (userGame == null)
                    return Results.NotFound(new { message = "Jogo não encontrado na biblioteca." });

                db.UserGames.Remove(userGame);
                await db.SaveChangesAsync();

                return Results.Ok(new { message = "Jogo removido da biblioteca." });
            })
            .WithTags("Biblioteca");

            app.Run();
        }

        // 🔧 Geração de Token JWT
        private static string GenerateJwtToken(User user, IConfiguration config)
        {
            var key = config["Jwt:Key"]!;
            var issuer = config["Jwt:Issuer"]!;
            var audience = config["Jwt:Audience"]!;

            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.Role, user.Role)
            };

            var creds = new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)),
                SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: claims,
                expires: DateTime.UtcNow.AddHours(2),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }

    // 🧱 DTOs auxiliares
    public record ChangePasswordRequest(string CurrentPassword, string NewPassword);
    public record UserRegister(string Name, string Email, string PasswordHash);
    public record UserLogin(string Email, string PasswordHash);
}
