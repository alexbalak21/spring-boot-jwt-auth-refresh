# Spring Boot JWT Authentication with Refresh Tokens

## Table of Contents
1. [Overview](#overview)
2. [Features](#features)
3. [Tech Stack](#tech-stack)
4. [Project Structure](#project-structure)
5. [Setup & Installation](#setup--installation)
6. [API Endpoints](#api-endpoints)
7. [Authentication Flow](#authentication-flow)
8. [Security Configuration](#security-configuration)
9. [Troubleshooting](#troubleshooting)
10. [License](#license)

## Overview
This project implements a secure RESTful API with JWT (JSON Web Token) authentication and refresh token mechanism. It provides user registration, login, and protected endpoints with role-based access control.

## Features
- User registration and authentication
- JWT-based stateless authentication
- Refresh token mechanism
- Role-based authorization (ADMIN/USER)
- Secure password storage with BCrypt
- RESTful API design
- Input validation
- Comprehensive error handling

## Tech Stack
- **Backend**: Spring Boot 3.x
- **Security**: Spring Security 6.x
- **Database**: H2 (in-memory, for demo)
- **Authentication**: JWT (JSON Web Tokens)
- **Build Tool**: Maven
- **Java Version**: 17
- **Lombok**: For reducing boilerplate code
- **Validation**: Jakarta Validation API

## Project Structure
```
src/main/java/app/
├── config/           # Configuration classes
│   └── SecurityConfig.java
├── controller/       # REST controllers
│   ├── AuthController.java
│   └── ProductController.java
├── dto/              # Data Transfer Objects
│   ├── LoginRequest.java
│   ├── RegisterRequest.java
│   ├── RefreshTokenRequest.java
│   └── TokenPair.java
├── model/            # JPA entities
│   ├── User.java
│   ├── Role.java
│   └── Product.java
├── repository/       # Data access layer
│   └── UserRepository.java
└── service/          # Business logic
    ├── AuthService.java
    └── JwtService.java
```

## Setup & Installation

### Prerequisites
- Java 17 or higher
- Maven 3.6 or higher

### Steps
1. Clone the repository
2. Configure the application properties:
   ```properties
   # Server
   server.port=8080
   
   # JWT Configuration
   app.jwt.auth-secret=your-256-bit-secret
   app.jwt.refresh-secret=your-refresh-secret
   app.jwt.auth-expiration=86400000        # 24 hours
   app.jwt.refresh-expiration=604800000    # 7 days
   ```
3. Build the project:
   ```bash
   mvn clean install
   ```
4. Run the application:
   ```bash
   mvn spring-boot:run
   ```

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register a new user
- `POST /api/auth/login` - Authenticate and get JWT tokens
- `POST /api/auth/refresh` - Get new access token using refresh token

### Products (Requires Authentication)
- `GET /api/products` - Get all products
- `GET /api/products/{id}` - Get product by ID
- `POST /api/products` - Create a new product (ADMIN only)
- `PUT /api/products/{id}` - Update a product (ADMIN only)
- `DELETE /api/products/{id}` - Delete a product (ADMIN only)

## Authentication Flow

1. **Registration**:
   - User provides username, password, and other details
   - System hashes the password and creates a new user account

2. **Login**:
   - User provides credentials
   - System validates credentials and returns JWT access token and refresh token

3. **Accessing Protected Resources**:
   - Client includes JWT in Authorization header
   - Server validates token and grants access if valid

4. **Token Refresh**:
   - When access token expires, client sends refresh token
   - Server validates refresh token and issues new access token

## Security Configuration
- JWT-based authentication
- Role-based access control
- Password encryption with BCrypt
- CSRF protection (disabled for API)
- Session management is stateless
- CORS configuration

## Troubleshooting

### Common Issues
1. **401 Unauthorized**
   - Check if the token is expired
   - Verify the token is correctly included in the Authorization header
   - Ensure the token has the required role

2. **400 Bad Request**
   - Validate request body matches expected format
   - Check required fields

3. **403 Forbidden**
   - Verify user has the required role
   - Check token signature and issuer

4. **Refresh Token Not Working**
   - Ensure refresh token hasn't expired
   - Verify the refresh token is valid and not blacklisted
   - Check if the token format is correct (should not include "Bearer " prefix)

## License
[Specify your license here]

---

For any questions or issues, please open an issue in the repository.
