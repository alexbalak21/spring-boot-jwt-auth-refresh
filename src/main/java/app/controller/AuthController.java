package app.controller;

import app.dto.*;
import app.model.User;
import app.service.AuthService;
import app.service.JwtService;
import app.service.RefreshTokenBlacklistService;
import io.jsonwebtoken.Claims;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.*;

import java.util.Date;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final JwtService jwtService;
    private final RefreshTokenBlacklistService refreshTokenBlacklistService;

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

    /**
     * DEBUG ENDPOINT: Manually blacklist a refresh token
     * WARNING: This is for debugging purposes only and should be removed in production
     */
    @PostMapping("/debug/blacklist-refresh-token")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> debugBlacklistRefreshToken(@RequestParam String refreshToken) {
        try {
            log.debug("Attempting to blacklist refresh token");
            
            // First try to validate the token
            Optional<Claims> claimsOpt = jwtService.extractClaims(refreshToken, true);
            
            String tokenId;
            String username;
            Date expiration;
            
            if (claimsOpt.isPresent()) {
                // Token is valid, extract info from claims
                Claims claims = claimsOpt.get();
                tokenId = claims.getId();
                username = claims.getSubject();
                expiration = claims.getExpiration();
                log.debug("Extracted token info from valid token - ID: {}, Username: {}, Expires: {}", 
                    tokenId, username, expiration);
            } else {
                // If token is invalid (e.g., already expired), try to extract info directly
                log.warn("Token validation failed, attempting to extract info directly");
                
                // Try to get token ID directly from token string
                tokenId = jwtService.extractTokenIdFromString(refreshToken)
                    .orElseThrow(() -> new IllegalArgumentException("Could not extract token ID from refresh token"));
                
                // For expired/invalid tokens, we might not be able to get all claims
                // You might want to get this info from your database or another source
                username = "unknown";
                expiration = jwtService.extractExpiration(refreshToken).orElse(new Date(System.currentTimeMillis() + 3600000)); // Default to 1 hour
                log.debug("Extracted token ID from raw token - ID: {}", tokenId);
            }
            
            if (tokenId == null) {
                throw new IllegalArgumentException("Could not determine token ID");
            }
            
            // Blacklist the token
            refreshTokenBlacklistService.blacklistToken(
                tokenId,
                username,
                expiration != null ? expiration.toInstant() : java.time.Instant.now().plusSeconds(3600)
            );
            
            log.info("Successfully blacklisted refresh token for user: {}, token ID: {}", username, tokenId);
            return ResponseEntity.ok(Map.of(
                "status", "success",
                "message", "Refresh token blacklisted",
                "tokenId", tokenId,
                "username", username,
                "expiresAt", expiration != null ? expiration : new Date(System.currentTimeMillis() + 3600000)
            ));
            
        } catch (Exception e) {
            log.error("Error blacklisting refresh token: {}", e.getMessage(), e);
            return ResponseEntity.badRequest().body(Map.of(
                "status", "error",
                "message", e.getMessage()
            ));
        }
    }


    //DEBUG ENDPOINT
    @PostMapping("/validate-refresh")
    public ResponseEntity<?> validateRefreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        try {
            if (request.getRefreshToken() == null || request.getRefreshToken().isBlank()) {
                return ResponseEntity.badRequest().body(Map.of("valid", false, "error", "Refresh token is required"));
            }

            // Try to validate the refresh token
            boolean isValid = jwtService.isTokenValid(request.getRefreshToken(), true);

            if (isValid) {
                Optional<Claims> claims = jwtService.extractClaims(request.getRefreshToken(), true);
                String username = claims.map(Claims::getSubject).orElse("unknown");
                Date expiration = claims.map(Claims::getExpiration).orElse(null);

                return ResponseEntity.ok(Map.of(
                        "valid", true,
                        "username", username,
                        "expiresAt", expiration != null ? expiration.getTime() : null
                ));
            } else {
                return ResponseEntity.ok(Map.of("valid", false, "error", "Invalid refresh token"));
            }
        } catch (Exception e) {
            log.error("Error validating refresh token: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("valid", false, "error", "Error validating token"));
        }
    }

}