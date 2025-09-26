using System.Text;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;   // JWT
using BCrypt.Net;                        // BCrypt
using FCG.Users.Domain.Entities;
using FCG.Users.Infrastructure;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;    // Tokens
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

// EF Core InMemory
builder.Services.AddDbContext<UsersDbContext>(opt =>
    opt.UseInMemoryDatabase("UsersDb"));

// JWT config (simples, secret fixo para dev – mova para secrets/env no futuro)
var jwtSecret = "super_secret_dev_key_1234567890_LONGER_KEY"; // >= 32 chars
var key = Encoding.ASCII.GetBytes(jwtSecret);

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.RequireHttpsMetadata = false;
    options.SaveToken = true;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = false,
        ValidateAudience = false,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ClockSkew = TimeSpan.Zero
    };
});

builder.Services.AddAuthorization();

// Swagger com suporte a JWT
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Version = "v1",
        Title = "FCG Users API",
        Description = "API para gerenciamento de usuários"
    });

    var securityScheme = new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Description = "JWT Authorization header usando Bearer.",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT"
    };

    c.AddSecurityDefinition("Bearer", securityScheme);
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

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "FCG Users API v1");
        c.RoutePrefix = string.Empty;
    });
}

app.UseAuthentication();
app.UseAuthorization();

// Health
app.MapGet("/health", () => Results.Ok("FCG.Users.Api is healthy 🚀"));

// ---------------- USERS CRUD ---------------- //

// GET /users (apenas autenticado)
app.MapGet("/users", async (UsersDbContext db) =>
    await db.Users.ToListAsync())
    .RequireAuthorization();

// GET /users/{id}
app.MapGet("/users/{id}", async (Guid id, UsersDbContext db) =>
    await db.Users.FindAsync(id) is User user
        ? Results.Ok(user)
        : Results.NotFound())
    .RequireAuthorization();

// POST /users (cadastro com hash) - público
app.MapPost("/users", async (User inputUser, UsersDbContext db) =>
{
    if (await db.Users.AnyAsync(u => u.Email == inputUser.Email))
        return Results.BadRequest("Email já cadastrado.");

    var user = new User
    {
        Name = inputUser.Name,
        Email = inputUser.Email,
        PasswordHash = BCrypt.Net.BCrypt.HashPassword(inputUser.PasswordHash)
    };

    db.Users.Add(user);
    await db.SaveChangesAsync();
    return Results.Created($"/users/{user.Id}", user);
}).AllowAnonymous();

// PUT /users/{id}
app.MapPut("/users/{id}", async (Guid id, User inputUser, UsersDbContext db) =>
{
    var user = await db.Users.FindAsync(id);
    if (user is null) return Results.NotFound();

    user.Name = inputUser.Name;
    user.Email = inputUser.Email;

    if (!string.IsNullOrWhiteSpace(inputUser.PasswordHash))
        user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(inputUser.PasswordHash);

    await db.SaveChangesAsync();
    return Results.NoContent();
}).RequireAuthorization();

// DELETE /users/{id}
app.MapDelete("/users/{id}", async (Guid id, UsersDbContext db) =>
{
    var user = await db.Users.FindAsync(id);
    if (user is null) return Results.NotFound();

    db.Users.Remove(user);
    await db.SaveChangesAsync();
    return Results.NoContent();
}).RequireAuthorization();

// ---------------- LOGIN ---------------- //

// Público
app.MapPost("/login", async (User login, UsersDbContext db) =>
{
    var user = await db.Users.FirstOrDefaultAsync(u => u.Email == login.Email);
    if (user is null) return Results.Unauthorized();

    if (!BCrypt.Net.BCrypt.Verify(login.PasswordHash, user.PasswordHash))
        return Results.Unauthorized();

    var tokenHandler = new JwtSecurityTokenHandler();
    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Email, user.Email)
        }),
        Expires = DateTime.UtcNow.AddHours(1),
        SigningCredentials = new SigningCredentials(
            new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
    };
    var token = tokenHandler.CreateToken(tokenDescriptor);
    var jwt = tokenHandler.WriteToken(token);

    return Results.Ok(new { token = jwt });
}).AllowAnonymous();

app.Run();
