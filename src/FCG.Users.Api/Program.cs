using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Security.Claims;
using System.Text;
using System.IdentityModel.Tokens.Jwt;

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
                options.Events = new JwtBearerEvents
                {
                    OnAuthenticationFailed = context =>
                    {
                        Console.WriteLine($"Falha na autenticação: {context.Exception.Message}");
                        return Task.CompletedTask;
                    }
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
                    Description = "Insira o token JWT sem Bearer ou aspas.",
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

            // 👥 USERS CRUD
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

            app.MapGet("/users/{id}", async (Guid id, UsersDbContext db, HttpContext context) =>
            {
                var user = await db.Users.FindAsync(id);
                if (user == null) return Results.NotFound();

                var currentUserId = context.User.FindFirst("nameid")?.Value;
                if (user.Role != UserRole.Admin.ToString() && currentUserId != user.Id.ToString())
                    return Results.Forbid();

                return Results.Ok(user);
            }).RequireAuthorization("UserOrAdmin");

            app.MapPut("/users/{id}", async (Guid id, User updatedUser, UsersDbContext db, HttpContext context) =>
            {
                var user = await db.Users.FindAsync(id);
                if (user == null) return Results.NotFound();

                var currentUserId = context.User.FindFirst("nameid")?.Value;
                if (user.Role != UserRole.Admin.ToString() && currentUserId != user.Id.ToString())
                    return Results.Forbid();

                user.Name = updatedUser.Name;
                user.Email = updatedUser.Email;
                user.PasswordHash = updatedUser.PasswordHash;
                if (Enum.IsDefined(typeof(UserRole), updatedUser.Role))
                    user.Role = updatedUser.Role;
                else
                    return Results.BadRequest("Role deve ser 'Admin' ou 'User'.");

                await db.SaveChangesAsync();
                return Results.NoContent();
            }).RequireAuthorization("UserOrAdmin");

            app.MapDelete("/users/{id}", async (Guid id, UsersDbContext db) =>
            {
                var user = await db.Users.FindAsync(id);
                if (user == null) return Results.NotFound();

                db.Users.Remove(user);
                await db.SaveChangesAsync();
                return Results.NoContent();
            }).RequireAuthorization("AdminOnly");

            // 🔑 LOGIN
            app.MapPost("/login", async (UserLogin login, UsersDbContext db) =>
            {
                var user = await db.Users.FirstOrDefaultAsync(u => u.Email == login.Email && u.PasswordHash == login.PasswordHash);
                if (user == null) return Results.Unauthorized();

                var issuer = builder.Configuration["Jwt:Issuer"] ?? throw new InvalidOperationException("JWT Issuer não está configurado.");
                var audience = builder.Configuration["Jwt:Audience"] ?? throw new InvalidOperationException("JWT Audience não está configurado.");
                var token = GenerateJwtToken(user, jwtKey, issuer, audience);
                return Results.Ok(new { token });
            });

            // 🧩 NOVO ENDPOINT /me
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

            app.Run();
        }

        // 🔧 Geração de Token
        private static string GenerateJwtToken(User user, string key, string issuer, string audience)
        {
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim("email", user.Email),
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

    // 🧱 ENTIDADES E CONTEXTO
    public class User
    {
        public Guid Id { get; set; }
        public required string Name { get; set; }
        public required string Email { get; set; }
        public required string PasswordHash { get; set; }
        public required string Role { get; set; }
    }

    public class UserLogin
    {
        public required string Email { get; set; }
        public required string PasswordHash { get; set; }
    }

    public class UsersDbContext : DbContext
    {
        public UsersDbContext(DbContextOptions<UsersDbContext> options)
            : base(options)
        {
        }

        public DbSet<User> Users { get; set; }
    }
}
