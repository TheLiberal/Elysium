# Elysium Auth Server

A robust, production-ready authentication server built with Elysia.js and Bun. This project provides a secure, performant authentication system with features like JWT-based authentication, refresh tokens, and comprehensive security measures.

## Features

- 🔐 **Secure Authentication**
  - JWT-based access tokens
  - Refresh token rotation
  - HTTP-only cookie storage
  - Password hashing with bcrypt

- 🛡️ **Security First**
  - Rate limiting
  - IP blocking
  - Suspicious activity monitoring
  - CORS protection
  - Secure session management

- 📝 **Comprehensive Logging**
  - Request/response logging
  - Security event tracking
  - Error monitoring

- 🚀 **Performance**
  - Built on Bun runtime
  - Efficient database queries with Drizzle ORM
  - Optimized JWT operations

## API Endpoints

- `POST /auth/signup` - Create a new user account
- `POST /auth/login` - Authenticate user and receive tokens
- `POST /auth/refresh` - Refresh access token
- `POST /auth/logout` - Invalidate sessions
- `GET /api/protected` - Example protected route
- `GET /api/me` - Get current user information
- `GET /health` - Server health check

## Quick Start

1. Clone the repository:
```bash
git clone https://github.com/yourusername/elysium-auth.git
cd elysium-auth
```

2. Install dependencies:
```bash
bun install
```

3. Create a `.env` file:
```env
JWT_SECRET=your-secret-key
REFRESH_SECRET=your-refresh-secret
DATABASE_URL=your-database-url
```

4. Start the server:
```bash
bun run dev
```

## Development

To run tests:
```bash
bun test
```

To check types:
```bash
bun run typecheck
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
