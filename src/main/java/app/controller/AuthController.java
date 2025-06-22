package app.controller;

import app.dto.LoginRequest;
import app.dto.RegisterRequest;
import app.dto.TokenPair;
import app.dto.UserResponse;
import app.model.User;
import app.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.authentication.BadCredentialsException;

import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request) {
        User registeredUser = authService.register(request);
        return ResponseEntity.ok(UserResponse.fromUser(registeredUser));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> request) {
        log.info("Raw login request received: {}", request);
        
        if (request == null || request.get("username") == null || request.get("password") == null) {
            log.error("Invalid login request - missing username or password");
            throw new BadCredentialsException("Username and password are required");
        }
        
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setUsername(request.get("username"));
        loginRequest.setPassword(request.get("password"));
        
        log.info("Attempting login for user: '{}'", loginRequest.getUsername());
        
        try {
            TokenPair tokenPair = authService.login(loginRequest);
            log.info("Login successful for user: '{}'", loginRequest.getUsername());
            return ResponseEntity.ok(tokenPair);
        } catch (BadCredentialsException e) {
            log.error("Login failed - invalid credentials for user: {}", loginRequest.getUsername());
            throw e; // This will be handled by GlobalExceptionHandler
        } catch (Exception e) {
            log.error("Login failed for user '{}': {}", loginRequest.getUsername(), e.getMessage());
            throw new BadCredentialsException("Authentication failed");
        }
    }
}