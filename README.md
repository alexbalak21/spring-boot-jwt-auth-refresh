# Spring Boot JWT Authentication with Refresh Tokens

[![Java Version](https://img.shields.io/badge/Java-17%2B-brightgreen)](https://openjdk.org/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.x-6DB33F)](https://spring.io/projects/spring-boot)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A secure, production-ready Spring Boot application featuring JWT (JSON Web Token) authentication with refresh token mechanism, role-based authorization, and comprehensive security features.

## ✨ Features

- 🔐 JWT-based authentication with access and refresh tokens
- ♻️ Refresh token mechanism for secure token rotation
- 👥 Role-based access control (ADMIN/USER)
- 🔒 Secure password hashing with BCrypt
- 📝 Email-based user identification
- 🛡️ Input validation and sanitization
- 📱 RESTful API design following best practices
- ✅ Comprehensive test coverage

## 🚀 Quick Start

### Prerequisites

- ☕ Java 17 or higher
- 🏗️ Maven 3.6+
- 🐳 Docker (optional, for containerized deployment)
- 📡 Git (for version control)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/spring-boot-jwt-auth-refresh.git
   cd spring-boot-jwt-auth-refresh
   ```

2. **Configure application properties**
   Create `application.properties` in `src/main/resources/` with:
   ```properties
   # Server Configuration
   server.port=8080
   server.servlet.context-path=/api
   
   # JWT Configuration
   app.jwt.auth-secret=your-256-bit-secret-key-here-make-it-secure
   app.jwt.refresh-secret=your-refresh-secret-key-here-make-it-secure
   app.jwt.auth-expiration=86400000        # 24 hours
   app.jwt.refresh-expiration=604800000    # 7 days
   
   # Database Configuration (H2 in-memory for development)
   spring.datasource.url=jdbc:h2:mem:authdb
   spring.datasource.driverClassName=org.h2.Driver
   spring.datasource.username=sa
   spring.datasource.password=password
   spring.h2.console.enabled=true
   spring.h2.console.path=/h2-console
   
   # JPA/Hibernate
   spring.jpa.database-platform=org.hibernate.dialect.H2Dialect
   spring.jpa.hibernate.ddl-auto=update
   spring.jpa.show-sql=true
   
   # Logging
   logging.level.org.springframework.security=DEBUG
   logging.level.app=DEBUG
   ```

3. **Build and run**
   ```bash
   mvn clean install
   mvn spring-boot:run
   ```

   The application will be available at `http://localhost:8080`

## Documentation

- [API Documentation](DOCUMENTATION.md) - Detailed API reference and usage examples
- [Architecture Guide](ARCHITECTURE.md) - Technical architecture and design decisions
- [Testing Guide](TESTING.md) - How to run tests and write new ones

## 🔌 API Endpoints

### 🔐 Authentication

| Method | Endpoint | Description | Request Body |
|--------|----------|-------------|--------------|
| POST   | `/auth/register` | Register new user | `{ "email": "user@example.com", "username": "user", "password": "password123", "role": "USER" }` |
| POST   | `/auth/login` | Authenticate user | `{ "username": "user", "password": "password123" }` |
| POST   | `/auth/refresh` | Get new access token | `{ "refreshToken": "your-refresh-token" }` |
| POST   | `/auth/logout` | Invalidate tokens | `{ "refreshToken": "your-refresh-token" }` |

### 📦 Products (Requires Authentication)

| Method | Endpoint | Description | Required Role |
|--------|----------|-------------|---------------|
| GET    | `/products` | Get all products | USER, ADMIN |
| GET    | `/products/{id}` | Get product by ID | USER, ADMIN |
| POST   | `/products` | Create new product | ADMIN |
| PUT    | `/products/{id}` | Update product | ADMIN |
| DELETE | `/products/{id}` | Delete product | ADMIN |

### Example Requests

**Register a new user:**
```http
POST /api/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "username": "user",
  "password": "password123",
  "role": "USER"
}
```

**Login:**
```http
POST /api/auth/login
Content-Type: application/json

{
  "username": "user",
  "password": "password123"
}
```

**Get protected resource:**
```http
GET /api/products
Authorization: Bearer your-access-token
```

## 🔒 Security Features

- **JWT Authentication**
  - Stateless authentication with access and refresh tokens
  - Configurable token expiration times
  - Secure token storage in HTTP-only cookies (optional)
  
- **Access Control**
  - Role-based authorization (ADMIN/USER)
  - Method-level security annotations
  - Protected endpoints with proper access controls
  
- **Data Protection**
  - BCrypt password hashing
  - Input validation and sanitization
  - Secure password requirements
  
- **HTTP Security**
  - CSRF protection (disabled for API endpoints)
  - CORS configuration
  - Security headers (XSS protection, HSTS, etc.)
  - Secure session management
  
- **Validation**
  - Request body validation
  - Email format validation
  - Password strength requirements
  - Input sanitization

## Testing

Run tests with:
```bash
mvn test
```

## Built With

- [Spring Boot](https://spring.io/projects/spring-boot) - Application framework
- [Spring Security](https://spring.io/projects/spring-security) - Authentication and authorization
- [JJWT](https://github.com/jwtk/jjwt) - JWT implementation
- [Lombok](https://projectlombok.org/) - Boilerplate reduction
- [H2 Database](https://www.h2database.com/) - In-memory database (for demo)
- [Maven](https://maven.apache.org/) - Dependency management

## Contributing

Contributions are welcome! Please read our [contributing guidelines](CONTRIBUTING.md) to get started.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📬 Contact

Alex - [@your_twitter](https://twitter.com/your_twitter) - your.email@example.com

🔗 Project Link: [https://github.com/yourusername/spring-boot-jwt-auth-refresh](https://github.com/yourusername/spring-boot-jwt-auth-refresh)

## 🙏 Acknowledgments

- [Spring Security Documentation](https://spring.io/projects/spring-security)
- [JWT Introduction](https://jwt.io/introduction/)
- [Baeldung Spring Security](https://www.baeldung.com/security-spring)
- [Spring Boot Reference](https://docs.spring.io/spring-boot/docs/current/reference/html/)
- [H2 Database](https://www.h2database.com/)
- [JJWT](https://github.com/jwtk/jjwt)

## Acknowledgments

- [Spring Security Documentation](https://spring.io/projects/spring-security)
- [JWT Introduction](https://jwt.io/introduction/)
- [Baeldung Spring Security](https://www.baeldung.com/security-spring)
- [Spring Boot Reference](https://docs.spring.io/spring-boot/docs/current/reference/html/)
