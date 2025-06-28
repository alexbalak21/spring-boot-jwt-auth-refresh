package app.service;

import app.dto.TokenPair;
import app.repository.AuthTokenBlackListRepository;
import app.repository.RefreshTokenBlacklistRepository;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.*;
import java.util.function.Function;

/**
 * Service responsible for JWT (JSON Web Token) generation, validation, and processing.
 * This service handles the complete JWT lifecycle including:
 * - Token generation (both access and refresh tokens)
 * - Token validation and verification
 * - Token parsing and claims extraction
 * - Key management for signing and verification
 * 
 * <p>Uses separate signing keys and expiration times for access and refresh tokens
 * for enhanced security. The service is designed to be stateless and thread-safe.
 * 
 * @see io.jsonwebtoken.Jwts JWT Builder and Parser
 * @see io.jsonwebtoken.Claims JWT Claims
 * @see org.springframework.security.core.Authentication Spring Security Authentication
 */
@Service
@Slf4j
public class JwtService {
    /**
     * Secret key for signing access tokens.
     */
    @Value("${app.jwt.auth-secret}")
    private String secretKey;

    /**
     * Secret key for signing refresh tokens.
     */
    @Value("${app.jwt.refresh-secret}")
    private String refreshSecretKey;

    /**
     * Expiration time for access tokens in milliseconds.
     */
    @Value("${app.jwt.auth-expiration}")
    private long expirationTime;

    /**
     * Expiration time for refresh tokens in milliseconds.
     */
    @Value("${app.jwt.refresh-expiration}")
    private long refreshExpirationTime;

    /**
     * Standard JWT token prefix.
     */
    private static final String TOKEN_PREFIX = "Bearer ";

    private final AuthTokenBlackListRepository tokenBlackListRepository;
    private final RefreshTokenBlacklistRepository refreshTokenBlacklistRepository;

    public JwtService(AuthTokenBlackListRepository tokenBlackListRepository, RefreshTokenBlacklistRepository refreshTokenBlacklistRepository) {
        this.tokenBlackListRepository = tokenBlackListRepository;
        this.refreshTokenBlacklistRepository = refreshTokenBlacklistRepository;
    }


    /**
     * Generates a new JWT access token for the authenticated user.
     *
     * @param authentication The authentication object containing user details
     * @return A signed JWT access token with Bearer prefix
     */
    public String generateAccessToken(Authentication authentication) {
        UserDetails userPrincipal = (UserDetails) authentication.getPrincipal();
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expirationTime);
        String jti = UUID.randomUUID().toString();

        return TOKEN_PREFIX + Jwts.builder()
                .header().add("typ", "JWT").and().id(jti)
                .subject(userPrincipal.getUsername())
                .claim("tokenType", "accessToken")
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(getAccessSigningKey())
                .compact();
    }

    /**
     * Generates a new JWT refresh token for the authenticated user.
     * Refresh tokens have a longer expiration time than access tokens.
     *
     * @param authentication The authentication object containing user details
     * @return A signed JWT refresh token with Bearer prefix
     */
    public String generateRefreshToken(Authentication authentication) {
        UserDetails userPrincipal = (UserDetails) authentication.getPrincipal();
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + refreshExpirationTime);
        String jti = UUID.randomUUID().toString();

        Map<String, String> claims = new HashMap<>();
        claims.put("tokenType", "refreshToken");

        return TOKEN_PREFIX + Jwts.builder()
                .header().add("typ", "JWT").and().id(jti)
                .subject(userPrincipal.getUsername())
                .claims(claims)
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(getRefreshSigningKey())
                .compact();
    }

    /**
     * Validates if the provided token is valid for the given user details.
     *
     * @param token The JWT token to validate
     * @param userDetails The user details to validate against
     * @return true if the token is valid for the user, false otherwise
     */
    public boolean validateToken(String token, UserDetails userDetails) {
        //IF TOKEN IN BLACKLIST, RETURN FALSE
        String jti = extractTokenId(token).orElse(null);
        if (tokenBlackListRepository.existsByJti(jti)) {
            log.debug("Token '{}' is in the blacklist.", token);
            return false;
        }
        try {
            Optional<String> extractedUsername = usernameFromToken(token);
            if (extractedUsername.isPresent()) {
                boolean matches = extractedUsername.get().equals(userDetails.getUsername());
                log.debug("Token validation for user '{}': {}", userDetails.getUsername(), matches);
                return matches;
            }
            log.warn("Token did not contain a valid username.");
        } catch (Exception e) {
            log.error("Exception during token validation: {}", e.getMessage(), e);
        }
        return false;
    }

    /**
     * Extracts the username from a JWT token (assumes access token by default).
     *
     * @param token The JWT token
     * @return An Optional containing the username if found, empty otherwise
     */
    public Optional<String> usernameFromToken(String token) {
        return usernameFromToken(token, false);
    }

    /**
     * Extracts the username from a JWT token, handling both access and refresh tokens.
     *
     * @param token The JWT token
     * @param isRefreshToken Whether the token is a refresh token
     * @return An Optional containing the username if found, empty otherwise
     */
    public Optional<String> usernameFromToken(String token, boolean isRefreshToken) {
        Optional<Claims> claims = extractClaims(token, isRefreshToken);
        String username = claims.map(Claims::getSubject).orElse(null);
        log.debug("Extracted username from {} token: {}", isRefreshToken ? "refresh" : "access", username);
        return Optional.ofNullable(username);
    }

    /**
     * Checks if a token is valid (assumes access token by default).
     *
     * @param token The JWT token to validate
     * @return true if the token is valid, false otherwise
     */
    public boolean isTokenValid(String token) {
        return isTokenValid(token, false);
    }

    /**
     * Checks if a token is valid, handling both access and refresh tokens.
     *
     * @param token The JWT token to validate
     * @param isRefreshToken Whether the token is a refresh token
     * @return true if the token is valid, false otherwise
     */
    public boolean isTokenValid(String token, boolean isRefreshToken) {
        String jti = extractTokenId(token, true).orElse(null);
        if (refreshTokenBlacklistRepository.existsByTokenId(jti)) return false;
        boolean valid = extractClaims(token, isRefreshToken).isPresent();
        log.debug("Token validity check ({}): {}", isRefreshToken ? "refresh" : "access", valid);
        return valid;
    }

    /**
     * Extracts claims from a JWT token (assumes access token by default).
     *
     * @param token The JWT token
     * @return An Optional containing the claims if successful, empty otherwise
     */
    public Optional<Claims> extractClaims(String token) {
        return extractClaims(token, false);
    }

    /**
     * Extracts claims from a JWT token, handling both access and refresh tokens.
     * Performs token type validation and handles various JWT exceptions.
     *
     * @param token The JWT token
     * @param isRefreshToken Whether the token is a refresh token
     * @return An Optional containing the claims if successful, empty otherwise
     */
    public Optional<Claims> extractClaims(String token, boolean isRefreshToken) {
        if (token == null || token.trim().isEmpty()) {
            log.warn("Token is null or empty");
            return Optional.empty();
        }

        try {
            log.debug("Starting token validation. Is refresh token: {}", isRefreshToken);
            log.trace("Token content: {}", token);
            
            // Get the appropriate signing key
            SecretKey key = isRefreshToken ? getRefreshSigningKey() : getAccessSigningKey();
            log.debug("Using {} key for validation", isRefreshToken ? "refresh" : "access");
            
            // Parse and verify the token
            Claims claims = Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();

            // Verify token type claim
            String expectedType = isRefreshToken ? "refreshToken" : "accessToken";
            String actualType = claims.get("tokenType", String.class);
            
            log.debug("Token claims - Subject: {}, Type: {}, Issued: {}, Expires: {}", 
                claims.getSubject(), 
                actualType,
                claims.getIssuedAt(),
                claims.getExpiration());

            if (!expectedType.equals(actualType)) {
                log.warn("Token type mismatch: expected '{}', found '{}'", expectedType, actualType);
                return Optional.empty();
            }

            log.debug("Token validation successful for subject: '{}'", claims.getSubject());
            return Optional.of(claims);

        } catch (ExpiredJwtException e) {
            log.warn("Token expired at {}. Current time: {}", e.getClaims().getExpiration(), new Date());
        } catch (SignatureException e) {
            log.warn("Invalid signature. Error: {}", e.getMessage());
            log.debug("Token: {}", token);
        } catch (MalformedJwtException e) {
            log.warn("Malformed token: {}", e.getMessage());
            log.debug("Token: {}", token);
        } catch (UnsupportedJwtException e) {
            log.warn("Unsupported token: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.warn("Invalid token argument: {}", e.getMessage());
        } catch (Exception e) {
            log.error("Unexpected exception during claim extraction: {}", e.getMessage(), e);
        }
        return Optional.empty();
    }

    /**
     * Gets the signing key for access tokens.
     *
     * @return A SecretKey instance for signing access tokens
     */
    private SecretKey getAccessSigningKey() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));
    }

    /**
     * Gets the signing key for refresh tokens.
     *
     * @return A SecretKey instance for signing refresh tokens
     */
    private SecretKey getRefreshSigningKey() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(refreshSecretKey));
    }

    /**
     * Generates a pair of access and refresh tokens for the authenticated user.
     *
     * @param authentication The authentication object containing user details
     * @return A TokenPair containing both access and refresh tokens
     */
    public TokenPair generateTokenPair(Authentication authentication) {
        String accessToken = generateAccessToken(authentication);
        String refreshToken = generateRefreshToken(authentication);
        log.debug("Generated token pair for user '{}'", authentication.getName());
        return new TokenPair(accessToken, refreshToken);
    }

    /**
     * Checks if the provided token is a refresh token.
     *
     * @param token The JWT token to check
     * @return true if the token is a refresh token, false otherwise
     */
    public boolean isRefreshToken(String token) {
        return extractClaims(token, true).isPresent();
    }

    /**
     * Extracts the JWT ID (jti) from a token.
     *
     * @param token The JWT token
     * @return An Optional containing the JWT ID if present, empty otherwise
     */
    public Optional<String> extractTokenId(String token) {
        return extractClaims(token).map(Claims::getId);
    }

    public Optional<String> extractTokenId (String refreshToken, boolean isRefreshToken){
        return extractClaims(refreshToken, isRefreshToken).map(Claims::getId);
    }


    /**
     * Extracts the expiration date from a JWT token.
     *
     * @param token The JWT token
     * @return An Optional containing the expiration date if present, empty otherwise
     */
    public Optional<Date> extractExpiration(String token) {
        return extractClaims(token).map(Claims::getExpiration);
    }
    public Optional<Date> extractExpiration(String token, boolean isRefreshToken) {
        return extractClaims(token, isRefreshToken).map(Claims::getExpiration);
    }

    public String extractUsername(String token) {
        return extractClaims(token).map(Claims::getSubject).orElse(null);
    }

    public String extractUsername (String refreshToken, boolean isRefreshToken) {
        return extractClaims(refreshToken, isRefreshToken).map(Claims::getSubject).orElse(null);
    }

    public String extractJti(String accessToken) {
        return extractClaims(accessToken).map(Claims::getId).orElse(null);
    }

    public String extractJti(String refreshToken, boolean isRefreshToken) {
        return extractClaims(refreshToken, isRefreshToken).map(Claims::getId).orElse(null);
    }

    /**
     * Extracts the JWT ID (jti) directly from the token string without validation.
     * This is useful when the token might be expired or the signature doesn't match.
     *
     * @param token The JWT token string
     * @return An Optional containing the JWT ID if found, empty otherwise
     */
    public Optional<String> extractTokenIdFromString(String token) {
        if (token == null || token.trim().isEmpty()) {
            return Optional.empty();
        }
        try {
            // Split the token into parts
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                return Optional.empty();
            }
            
            // Decode the payload (second part)
            String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));
            
            // Parse the JSON payload to get the jti
            com.fasterxml.jackson.databind.JsonNode jsonNode = new com.fasterxml.jackson.databind.ObjectMapper()
                .readTree(payload);
                
            if (jsonNode.has("jti")) {
                return Optional.of(jsonNode.get("jti").asText());
            }
            return Optional.empty();
        } catch (Exception e) {
            log.warn("Failed to extract token ID from token string: {}", e.getMessage());
            return Optional.empty();
        }
    }
}