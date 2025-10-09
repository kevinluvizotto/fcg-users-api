using System;
using System.Text.Json.Serialization;

namespace FCG.Users.Domain.Entities
{
    public class UserGame
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public Guid UserId { get; set; }

        [JsonPropertyName("GameId")]
        public Guid GameId { get; set; }
    }
}
