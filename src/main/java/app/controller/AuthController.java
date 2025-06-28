package app.controller;

import app.dto.*;
import app.model.User;
import app.service.AuthService;
import app.service.CustomBlacklistRefreshToken;
import app.service.JwtService;
import app.service.RefreshTokenBlacklistService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final JwtService jwtService;
    private final RefreshTokenBlacklistService refreshTokenBlacklistService;
    private final CustomBlacklistRefreshToken customBlacklistRefreshToken;

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

    @PostMapping("/logout")
    public ResponseEntity<?> logout(
            @RequestHeader("Authorization") String authHeader,
            @Valid @RequestBody RefreshTokenRequest request) {
        try {
            // Extract the token from the Authorization header (remove 'Bearer ' prefix)
            String accessToken = authHeader.substring(7); // Remove 'Bearer ' prefix
            String refreshToken = request.getRefreshToken();
            if (refreshToken == null) {
                log.error("Refresh token is null");
                throw new BadCredentialsException("Refresh token is required");
            }

            if (!jwtService.isTokenValid(refreshToken, true)) {
                log.error("Refresh token is invalid");
                throw new BadCredentialsException("Invalid refresh token");
            }
            authService.logout(accessToken, refreshToken);
            return ResponseEntity.ok(Map.of("message", "You are logged out"));
        } catch (Exception e) {
            log.error("Logout failed: {}", e.getMessage());
            throw new BadCredentialsException("Logout failed");
        }
    }


    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        TokenPair tokenPair = authService.refreshTokens(request);
        return ResponseEntity.ok(tokenPair);
    }
}