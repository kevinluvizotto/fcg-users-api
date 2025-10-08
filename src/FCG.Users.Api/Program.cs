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

            // 🌍 HTTP Client para integração com Games API
            builder.Services.AddHttpClient();

            // 📘 Swagger
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen(c =>
            {
                c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    In = ParameterLocation.Header,
                    Description = "Insira o token JWT sem 'Bearer ' ou aspas.",
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
                if (!Enum.IsDefined(typeof(UserRole), user.Role))
                    return Results.BadRequest("Role deve ser 'Admin' ou 'User'.");

                if (await db.Users.AnyAsync(u => u.Email == user.Email))
                    return Results.BadRequest("Email já cadastrado.");

                user.Id = Guid.NewGuid();
                db.Users.Add(user);
                await db.SaveChangesAsync();
                return Results.Created($"/users/{user.Id}", user);
            }).RequireAuthorization("AdminOnly");

            app.MapGet("/users/{id}", async (Guid id, UsersDbContext db) =>
            {
                var user = await db.Users.FindAsync(id);
                return user is not null ? Results.Ok(user) : Results.NotFound();
            }).RequireAuthorization("UserOrAdmin");

            app.MapPut("/users/{id}", async (Guid id, User updatedUser, UsersDbContext db) =>
            {
                var user = await db.Users.FindAsync(id);
                if (user is null) return Results.NotFound();

                user.Name = updatedUser.Name;
                user.Email = updatedUser.Email;
                user.PasswordHash = updatedUser.PasswordHash;
                user.Role = updatedUser.Role;

                await db.SaveChangesAsync();
                return Results.NoContent();
            }).RequireAuthorization("UserOrAdmin");

            app.MapDelete("/users/{id}", async (Guid id, UsersDbContext db) =>
            {
                var user = await db.Users.FindAsync(id);
                if (user is null) return Results.NotFound();

                db.Users.Remove(user);
                await db.SaveChangesAsync();
                return Results.NoContent();
            }).RequireAuthorization("AdminOnly");

            // 🔑 LOGIN
            app.MapPost("/login", async (UserLogin login, UsersDbContext db, IConfiguration config) =>
            {
                var user = await db.Users.FirstOrDefaultAsync(u => u.Email == login.Email && u.PasswordHash == login.PasswordHash);
                if (user is null) return Results.Unauthorized();

                var token = GenerateJwtToken(user, config);
                return Results.Ok(new { token });
            });

            // 🆕 REGISTRO PÚBLICO (Primeiro Acesso)
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
            })
            .WithName("RegisterUser")
            .WithTags("Autenticação");

            // 🧩 PERFIL AUTENTICADO
            app.MapGet("/me", [Authorize] async (HttpContext http, UsersDbContext db) =>
            {
                var userId = http.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                if (string.IsNullOrEmpty(userId))
                    return Results.Unauthorized();

                var user = await db.Users.FindAsync(Guid.Parse(userId));
                if (user == null)
                    return Results.NotFound(new { message = "Usuário não encontrado." });

                return Results.Ok(new
                {
                    user.Id,
                    user.Name,
                    user.Email,
                    user.Role
                });
            })
            .WithName("GetCurrentUser")
            .WithTags("Perfil")
            .RequireAuthorization();

            // 🔒 ALTERAR SENHA
            app.MapPut("/me/password", [Authorize] async (HttpContext http, UsersDbContext db, ChangePasswordRequest req) =>
            {
                var userId = http.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                if (string.IsNullOrEmpty(userId))
                    return Results.Unauthorized();

                var user = await db.Users.FindAsync(Guid.Parse(userId));
                if (user == null)
                    return Results.NotFound(new { message = "Usuário não encontrado." });

                if (user.PasswordHash != req.CurrentPassword)
                    return Results.BadRequest(new { message = "Senha atual incorreta." });

                user.PasswordHash = req.NewPassword;
                await db.SaveChangesAsync();

                return Results.Ok(new { message = "Senha alterada com sucesso." });
            })
            .WithName("ChangePassword")
            .WithTags("Perfil")
            .RequireAuthorization();

            // 🎮 BIBLIOTECA DE JOGOS (proxy para Games API)
            app.MapGet("/users/me/games", [Authorize] async (IHttpClientFactory httpFactory, HttpContext context, IConfiguration config) =>
            {
                var token = context.Request.Headers["Authorization"].ToString();
                if (string.IsNullOrEmpty(token))
                    return Results.Unauthorized();

                // ✅ Agora busca os jogos diretamente da loja (/games), não /me/games
                var httpClient = httpFactory.CreateClient();
                var gamesApiUrl = $"{config["GamesApi:BaseUrl"]}/games";

                var request = new HttpRequestMessage(HttpMethod.Get, gamesApiUrl);
                request.Headers.Add("Authorization", token);

                var response = await httpClient.SendAsync(request);
                var json = await response.Content.ReadAsStringAsync();

                return Results.Content(json, "application/json");
            })
            .WithName("GetMyGames")
            .WithTags("Biblioteca")
            .RequireAuthorization();


            app.MapPost("/users/me/games", [Authorize] async (IHttpClientFactory httpFactory, HttpContext context, IConfiguration config) =>
            {
                var token = context.Request.Headers["Authorization"].ToString();
                var gameId = context.Request.Query["gameId"].ToString();
                if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(gameId))
                    return Results.BadRequest(new { message = "Token ou gameId ausente." });

                // ✅ Agora o POST também usa /games (não /me/games)
                var httpClient = httpFactory.CreateClient();
                var gamesApiUrl = $"{config["GamesApi:BaseUrl"]}/games?gameId={gameId}";

                var request = new HttpRequestMessage(HttpMethod.Post, gamesApiUrl);
                request.Headers.Add("Authorization", token);

                var response = await httpClient.SendAsync(request);
                var json = await response.Content.ReadAsStringAsync();

                return Results.Content(json, "application/json");
            })
            .WithName("BuyGame")
            .WithTags("Biblioteca")
            .RequireAuthorization();


            app.MapDelete("/users/me/games/{gameId}", [Authorize] async (IHttpClientFactory httpFactory, HttpContext context, IConfiguration config, Guid gameId) =>
            {
                var token = context.Request.Headers["Authorization"].ToString();
                if (string.IsNullOrEmpty(token))
                    return Results.BadRequest(new { message = "Token ausente." });

                // Mantém /games/{gameId} (sem /me)
                var httpClient = httpFactory.CreateClient();
                var gamesApiUrl = $"{config["GamesApi:BaseUrl"]}/games/{gameId}";

                var request = new HttpRequestMessage(HttpMethod.Delete, gamesApiUrl);
                request.Headers.Add("Authorization", token);

                var response = await httpClient.SendAsync(request);
                var json = await response.Content.ReadAsStringAsync();

                return Results.Content(json, "application/json");
            })
            .WithName("RemoveGameFromLibrary")
            .WithTags("Biblioteca")
            .RequireAuthorization();

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

            var keyBytes = Encoding.UTF8.GetBytes(key);
            var signingCredentials = new SigningCredentials(new SymmetricSecurityKey(keyBytes), SecurityAlgorithms.HmacSha256);
            var token = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: claims,
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: signingCredentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }

    // 🧱 ENTIDADES AUXILIARES
    public record ChangePasswordRequest(string CurrentPassword, string NewPassword);
    public record UserRegister(string Name, string Email, string PasswordHash);
    public record UserLogin(string Email, string PasswordHash);
}
