# Spring Boot JWT Authentication with Refresh Tokens

[![Java Version](https://img.shields.io/badge/Java-17%2B-brightgreen)](https://openjdk.org/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.x-6DB33F)](https://spring.io/projects/spring-boot)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A secure, production-ready Spring Boot application featuring JWT (JSON Web Token) authentication with refresh token mechanism, role-based authorization, and comprehensive security features.

## Features

- JWT-based authentication
- Refresh token mechanism
- Role-based access control (ADMIN/USER)
- Secure password hashing with BCrypt
- RESTful API design
- Input validation
- Comprehensive documentation
- Test coverage

## Quick Start

### Prerequisites

- Java 17 or higher
- Maven 3.6+
- Git (optional)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/spring-boot-jwt-auth-refresh.git
   cd spring-boot-jwt-auth-refresh
   ```

2. **Configure application properties**
   Create `application.properties` in `src/main/resources/` with:
   ```properties
   # Server
   server.port=8080
   
   # JWT Configuration
   app.jwt.auth-secret=your-256-bit-secret-key-here-make-it-secure
   app.jwt.refresh-secret=your-refresh-secret-key-here-make-it-secure
   app.jwt.auth-expiration=86400000        # 24 hours
   app.jwt.refresh-expiration=604800000    # 7 days
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

## API Endpoints

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST   | `/api/auth/register` | Register a new user |
| POST   | `/api/auth/login` | Authenticate and get JWT tokens |
| POST   | `/api/auth/refresh` | Get new access token using refresh token |

### Products (Requires Authentication)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | `/api/products` | Get all products |
| GET    | `/api/products/{id}` | Get product by ID |
| POST   | `/api/products` | Create new product (ADMIN) |
| PUT    | `/api/products/{id}` | Update product (ADMIN) |
| DELETE | `/api/products/{id}` | Delete product (ADMIN) |

## Security

- JWT-based stateless authentication
- Role-based access control
- Password encryption with BCrypt
- CSRF protection (disabled for API)
- CORS configuration
- Secure headers
- Input validation

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

## License

Distributed under the MIT License. See `LICENSE` for more information.

## Contact

Your Name - [@your_twitter](https://twitter.com/your_twitter) - email@example.com

Project Link: [https://github.com/yourusername/spring-boot-jwt-auth-refresh](https://github.com/yourusername/spring-boot-jwt-auth-refresh)

## Acknowledgments

- [Spring Security Documentation](https://spring.io/projects/spring-security)
- [JWT Introduction](https://jwt.io/introduction/)
- [Baeldung Spring Security](https://www.baeldung.com/security-spring)
- [Spring Boot Reference](https://docs.spring.io/spring-boot/docs/current/reference/html/)
