package app.service;

import app.dto.TokenPair;
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
 * Service responsible for JWT token generation, validation, and processing.
 * Handles both access and refresh tokens with separate signing keys and expiration times.
 */
@Service
@Slf4j
public class JwtService {

    /**
     * Secret key for signing access tokens.
     */
    @Value("${app.jwt.authSecret}")
    private String secretKey;

    /**
     * Secret key for signing refresh tokens.
     */
    @Value("${app.jwt.refreshSecret}")
    private String refreshSecretKey;

    /**
     * Expiration time for access tokens in milliseconds.
     */
    @Value("${app.jwt.AuthExpiration}")
    private long expirationTime;

    /**
     * Expiration time for refresh tokens in milliseconds.
     */
    @Value("${app.jwt.refreshExpiration}")
    private long refreshExpirationTime;

    /**
     * Standard JWT token prefix.
     */
    private static final String TOKEN_PREFIX = "Bearer ";

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

        Map<String, String> claims = new HashMap<>();
        claims.put("tokenType", "refreshToken");

        return TOKEN_PREFIX + Jwts.builder()
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
        try {
            SecretKey key = isRefreshToken ? getRefreshSigningKey() : getAccessSigningKey();
            Claims claims = Jwts.parser().verifyWith(key).build()
                    .parseSignedClaims(token).getPayload();

            String expectedType = isRefreshToken ? "refreshToken" : "accessToken";
            String actualType = claims.get("tokenType", String.class);

            if (!expectedType.equals(actualType)) {
                log.warn("Token type mismatch: expected '{}', found '{}'", expectedType, actualType);
                return Optional.empty();
            }

            log.debug("Extracted claims successfully: subject='{}', type='{}'", claims.getSubject(), actualType);
            return Optional.of(claims);

        } catch (ExpiredJwtException e) {
            log.warn("Token expired: {}", e.getMessage());
        } catch (SignatureException e) {
            log.warn("Invalid signature: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            log.warn("Malformed token: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.warn("Unsupported token: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.warn("Empty claims string: {}", e.getMessage());
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
}