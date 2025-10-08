using FCG.Users.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace FCG.Users.Infrastructure;

public class UsersDbContext : DbContext
{
    public UsersDbContext(DbContextOptions<UsersDbContext> options) : base(options)
    {
    }

    public DbSet<User> Users => Set<User>();
    public DbSet<UserGame> UserGames => Set<UserGame>(); 

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        // --- USERS ---
        modelBuilder.Entity<User>(entity =>
        {
            entity.HasKey(u => u.Id);
            entity.Property(u => u.Name).IsRequired().HasMaxLength(100);
            entity.Property(u => u.Email).IsRequired().HasMaxLength(200);
            entity.HasIndex(u => u.Email).IsUnique();
        });

        // --- USERGAMES ---
        modelBuilder.Entity<UserGame>(entity =>
        {
            entity.HasKey(ug => ug.Id);
            entity.Property(ug => ug.UserId).IsRequired();
            entity.Property(ug => ug.GameId).IsRequired();

            // 🔗 Índices para performance e integridade
            entity.HasIndex(ug => new { ug.UserId, ug.GameId }).IsUnique();
        });
    }
}
