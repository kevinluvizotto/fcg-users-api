namespace FCG.Users.Domain.Entities;

public class UserGame
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid UserId { get; set; }
    public Guid GameId { get; set; }
}
