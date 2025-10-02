# FCG Users API

API de Usuários da plataforma **FIAP Cloud Games (FCG)**.  
Parte do projeto da **Fase 3** (migração para microsserviços).

---

## 🚀 Tecnologias
- .NET 8 (Minimal APIs)
- Entity Framework Core (InMemory para dev)
- JWT Authentication (JSON Web Token)
- BCrypt (hash de senhas)
- Swagger (documentação e testes de endpoints)
- Docker

---

## 📦 Como rodar localmente

### Pré-requisitos
- .NET 8 SDK.
- (Opcional) Docker.

### Passos
# Restaurar pacotes e compilar
dotnet build fcg-users-api.sln

# Rodar a API
dotnet run --project src/FCG.Users.Api
A aplicação sobe em:
👉 http://localhost:5192

Swagger UI disponível em:
👉 http://localhost:5192/swagger

🔑 Autenticação JWT
Criar usuário
POST /users
{
  "name": "Admin",
  "email": "admin@gmail.com",
  "passwordHash": "P@ssw0rd"
}
Fazer login
POST /login
{
  "email": "admin@gmail.com",
  "passwordHash": "P@ssw0rd"
}
Resposta:
{
  "token": "eyJhbGciOiJIUzI1NiIsInR..."
}
Authorize no Swagger
Clique em Authorize

Cole o token (sem escrever Bearer , apenas o token)

Execute os endpoints protegidos (/users, /users/{id}, etc.)

Endpoints principais
Health
GET /health → Status da API

Users
POST /users → Criar usuário (público)

POST /login → Login e geração de JWT (público)

GET /users → Listar usuários (autenticado)

GET /users/{id} → Buscar usuário (autenticado)

PUT /users/{id} → Atualizar usuário (autenticado)

DELETE /users/{id} → Remover usuário (autenticado)

Rodando com Docker

# Build da imagem
docker build -t fcg-users-api .

# Rodar container
docker run -d -p 5192:8080 fcg-users-api

# API Local
A API ficará disponível em:
http://localhost:5192






