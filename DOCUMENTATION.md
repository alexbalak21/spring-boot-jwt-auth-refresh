# 📚 Spring Boot JWT Authentication with Refresh Tokens

## 🔍 Overview
This documentation provides a comprehensive guide to the Spring Boot JWT Authentication application. It covers the architecture, security implementation, API reference, and setup instructions.

## 📋 Table of Contents
1. [Features](#features)
2. [Tech Stack](#tech-stack)
3. [Project Structure](#project-structure)
4. [Setup & Installation](#setup--installation)
5. [API Endpoints](#api-endpoints)
6. [Authentication Flow](#authentication-flow)
7. [Security Implementation](#security-implementation)
8. [Troubleshooting](#troubleshooting)
9. [License](#license)

## Overview
This project implements a secure RESTful API with JWT (JSON Web Token) authentication and refresh token mechanism. It provides user registration, login, and protected endpoints with role-based access control.

## ✨ Key Features

### 🔐 Authentication & Authorization
- **JWT-based Authentication**: Stateless authentication using JSON Web Tokens
- **Refresh Token Mechanism**: Token rotation with configurable expiration
- **Role-based Access Control**: Basic role-based permissions
- **Email-based Registration**: User registration with email and username

### 🛡️ Security
- **BCrypt Password Hashing**: Secure password storage
- **Token Blacklisting**: Invalidate tokens on logout
- **Input Validation**: Request validation using Jakarta Validation
- **Request Logging**: Detailed request/response logging

### 🚀 Performance
- **Stateless Architecture**: Horizontally scalable
- **In-memory Token Blacklist**: For immediate token invalidation
- **Connection Pooling**: Optimized database connections

## 🛠 Tech Stack

### Core Technologies
- **Java 17**: Latest LTS version
- **Spring Boot 3.x**: Rapid application development framework
- **Spring Security 6.x**: Authentication and authorization
- **Spring Data JPA**: Data access abstraction
- **H2 Database**: In-memory database for development
- **Maven**: Build automation and dependency management

### Security
- **JJWT**: JWT implementation for Java
- **BCrypt**: Password hashing algorithm
- **Jakarta Validation**: Input validation
- **Spring Security OAuth2**: OAuth2 support

### Development Tools
- **Lombok**: Boilerplate reduction
- **MapStruct**: Object mapping
- **JUnit 5 & Mockito**: Testing framework
- **SpringDoc OpenAPI**: API documentation

### Monitoring
- **Spring Boot Actuator**: Application metrics and health checks
- **Micrometer**: Application metrics
- **Logback**: Logging framework

## 🏗 Project Structure

```
src/main/java/app/
├── config/                   # Configuration classes
│   └── RequestLoggingConfig.java  # Request/Response logging
│
├── controller/               # REST controllers
│   ├── AuthController.java   # Authentication endpoints
│   ├── ProductController.java # Product management
│   └── TestController.java   # Test endpoints
│
├── dto/                      # Data Transfer Objects
│   ├── LoginRequest.java     # Login request DTO
│   ├── ProductDto.java       # Product DTO
│   ├── RefreshTokenRequest.java
│   ├── RegisterRequest.java
│   ├── TokenPair.java        # Access and refresh token pair
│   └── UserResponse.java     # User response DTO
│
├── model/                    # JPA entities
│   └── User.java             # User entity with authentication details
│
├── repository/               # Data access layer
│   ├── AuthTokenBlackListRepository.java
│   └── UserRepository.java
│
├── security/                 # Security related classes
│   └── CustomAuthenticationFailureHandler.java
│
├── service/                  # Business logic
│   ├── AuthService.java      # Authentication logic
│   ├── JwtService.java       # JWT token operations
│   ├── CustomBlacklistRefreshToken.java
│   └── RefreshTokenBlacklistService.java
│
├── exception/                # Exception handling
│   └── GlobalExceptionHandler.java
│
└── filter/                   # HTTP filters
    └── RequestLoggingFilter.java  # Request/Response logging
```

src/main/resources/
├── application.properties    # Application configuration
├── application-dev.properties # Development profile
└── application-prod.properties # Production profile
```

## ⚙️ Setup & Installation

### Prerequisites
- Java 17 or higher
- Maven 3.6 or higher
- Git (for version control)

### Configuration

#### 1. Application Properties

Create or modify `application.properties`:

```properties
# Server Configuration
server.port=8080

# JWT Configuration
app.jwt.auth-secret=your-256-bit-secure-key-here
app.jwt.refresh-secret=your-256-bit-refresh-secure-key-here
app.jwt.auth-expiration=86400000        # 24 hours
app.jwt.refresh-expiration=604800000    # 7 days

# Database Configuration (H2 in-memory)
spring.datasource.url=jdbc:h2:mem:authdb
spring.datasource.driver-class-name=org.h2.Driver
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
logging.pattern.console=%d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level %logger{36} - %msg%n

# Request/Response Logging
logging.level.org.springframework.web.filter.CommonsRequestLoggingFilter=DEBUG
logging.level.app.filter.RequestLoggingFilter=DEBUG
```

#### 2. Build and Run

```bash
# Clone the repository (if not already cloned)
git clone <repository-url>
cd spring-boot-jwt-auth-refresh

# Build the application
mvn clean install

# Run the application
mvn spring-boot:run
```

The application will be available at `http://localhost:8080`

#### 3. Access the Application

- API Base URL: `http://localhost:8080/api`
- H2 Console: `http://localhost:8080/h2-console`
  - JDBC URL: `jdbc:h2:mem:authdb`
  - Username: `sa`
  - Password: `password`

### Environment Variables

For production, consider using environment variables:

```bash
export JWT_AUTH_SECRET=your-secure-secret
export JWT_REFRESH_SECRET=your-secure-refresh-secret
export SPRING_PROFILES_ACTIVE=prod
```

### Production Configuration

For production, create `application-prod.properties`:

```properties
# Production Database (PostgreSQL example)
spring.datasource.url=jdbc:postgresql://localhost:5432/authdb
spring.datasource.username=dbuser
spring.datasource.password=dbpassword
spring.jpa.hibernate.ddl-auto=validate
spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect

# Disable H2 console in production
spring.h2.console.enabled=false

# Production logging
logging.level.org.springframework=WARN
logging.level.app=INFO
```

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register a new user
- `POST /api/auth/login` - Authenticate and get JWT tokens
- `POST /api/auth/refresh` - Get new access token using refresh token

#### Register User
- **URL**: `/api/auth/register`
- **Method**: `POST`
- **Request Body**:
  ```json
  {
    "username": "testuser",
    "email": "test@example.com",
    "password": "password123",
    "role": "USER"
  }
  ```
- **Success Response**: `200 OK`
  ```json
  {
    "id": 1,
    "username": "testuser",
    "email": "test@example.com",
    "role": "USER"
  }
  ```

#### Login
- **URL**: `/api/auth/login`
- **Method**: `POST`
- **Request Body**:
  ```json
  {
    "username": "testuser",
    "password": "password123"
  }
  ```
- **Success Response**: `200 OK`
  ```json
  {
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
  ```

#### Refresh Token
- **URL**: `/api/auth/refresh`
- **Method**: `POST`
- **Request Body**:
  ```json
  {
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
  ```
- **Success Response**: `200 OK`
  ```json
  {
    "accessToken": "new-access-token",
    "refreshToken": "new-refresh-token"
  }
  ```

#### Logout
- **URL**: `/api/auth/logout`
- **Method**: `POST`
- **Headers**:
  - `Authorization: Bearer <access_token>`
- **Request Body**:
  ```json
  {
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
  ```
- **Success Response**: `200 OK`
  ```json
  {
    "message": "You are logged out"
  }
  ```

### Test Endpoints

#### Public Endpoint
- **URL**: `/api/test/public`
- **Method**: `GET`
- **Response**: `200 OK`
  ```json
  {
    "message": "Public Content."
  }
  ```

#### Protected Endpoint
- **URL**: `/api/test/protected`
- **Method**: `GET`
- **Headers**:
  - `Authorization: Bearer <access_token>`
- **Response**: `200 OK`
  ```json
  {
    "message": "Protected Content."
  }
  ```

#### Admin Endpoint
- **URL**: `/api/test/admin`
- **Method**: `GET`
- **Headers**:
  - `Authorization: Bearer <access_token>`
- **Response**: `200 OK` (for users with ADMIN role)
  ```json
  {
    "message": "Admin Board."
  }
  ```

## 🔄 Authentication Flow

1. **User Registration**
   - Client sends a POST request to `/api/auth/register` with user details (username, email, password, role)
   - Server validates the request, hashes the password using BCrypt, and creates a new user
   - Returns the created user details (without sensitive information)

2. **User Login**
   - Client sends a POST request to `/api/auth/login` with username and password
   - Server authenticates the user using Spring Security's `AuthenticationManager`
   - On successful authentication, generates:
     - Access Token (short-lived, default 24 hours)
     - Refresh Token (longer-lived, default 7 days)
   - Returns both tokens to the client

3. **Accessing Protected Resources**
   - Client includes the access token in the `Authorization: Bearer <token>` header
   - Server validates the token for each request
   - If token is valid, request is processed
   - If token is expired, client should use the refresh token to get a new access token

4. **Token Refresh**
   - Client sends a POST to `/api/auth/refresh` with the refresh token
   - Server validates the refresh token (checks if not blacklisted and not expired)
   - If valid, issues a new access token and optionally a new refresh token
   - The old refresh token is blacklisted

5. **Logout**
   - Client sends a POST to `/api/auth/logout` with the refresh token
   - Server blacklists both the access token and refresh token
   - Client should remove both tokens from storage

## 🔒 Security Implementation

### JWT Token Handling
- **Access Token**: Short-lived (24h by default), used for authentication
- **Refresh Token**: Longer-lived (7 days by default), used to obtain new access tokens
- **Token Blacklisting**: Implemented to handle immediate token invalidation on logout
- **Token Validation**: Signature verification, expiration check, and blacklist check

### Security Features
- **Password Hashing**: BCrypt with strength 10
- **Request Validation**: Jakarta Bean Validation on all incoming requests
- **Role-based Access Control**: `@PreAuthorize` annotations for method-level security
- **CORS Configuration**: Enabled with sensible defaults
- **CSRF Protection**: Disabled for stateless API (handled by JWT)
- **Request Logging**: Detailed logging of requests and responses for debugging

### Token Storage
- **Client-side**: Tokens should be stored securely (HTTP-only cookies recommended)
- **Server-side**: Blacklisted tokens are stored in-memory

## 🐛 Troubleshooting

### Common Issues

1. **401 Unauthorized**
   - **Token Expired**: Check token expiration time and refresh if needed
   - **Invalid Token**: Verify token signature and format
   - **Missing Token**: Ensure `Authorization: Bearer <token>` header is included
   - **Blacklisted Token**: Token might have been invalidated due to logout

2. **400 Bad Request**
   - **Invalid Request Body**: Ensure all required fields are present and valid
   - **Validation Errors**: Check response body for specific validation messages
   - **Malformed JSON**: Verify JSON syntax in request body

3. **403 Forbidden**
   - **Insufficient Permissions**: User role doesn't have access to the resource
   - **Token Mismatch**: Refresh token doesn't match the user

4. **Refresh Token Issues**
   - **Expired**: Refresh token has exceeded its lifetime
   - **Blacklisted**: Token was invalidated (e.g., after logout)
   - **Invalid Format**: Ensure token is not prefixed with "Bearer "

5. **Database Connection**
   - **H2 Console**: Accessible at `/h2-console` (if enabled)
   - **Connection Pool**: Check for connection leaks in logs

## 📜 License

This project is licensed under the [MIT License](LICENSE).

---

For any questions or issues, please open an issue in the repository.
