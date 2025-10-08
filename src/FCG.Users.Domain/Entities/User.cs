namespace FCG.Users.Domain.Entities
{
    /// <summary>
    /// Entidade que representa o usuário da plataforma FCG.
    /// </summary>
    public class User
    {
        /// <summary>
        /// Identificador único do usuário.
        /// </summary>
        public Guid Id { get; set; } = Guid.NewGuid();

        /// <summary>
        /// Nome completo do usuário.
        /// </summary>
        public string Name { get; set; } = string.Empty;

        /// <summary>
        /// E-mail utilizado para login e identificação.
        /// </summary>
        public string Email { get; set; } = string.Empty;

        /// <summary>
        /// Hash da senha do usuário (não armazena a senha em texto puro).
        /// </summary>
        public string PasswordHash { get; set; } = string.Empty;

        /// <summary>
        /// Papel (Role) do usuário na aplicação. Pode ser "Admin" ou "User".
        /// </summary>
        public string Role { get; set; } = "User";
    }
}
