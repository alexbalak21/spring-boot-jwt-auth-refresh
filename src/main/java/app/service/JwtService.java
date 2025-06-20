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

@Service
@Slf4j
public class JwtService {

    @Value("${app.jwt.authSecret}")
    private String secretKey;

    @Value("${app.jwt.refreshSecret}")
    private String refreshSecretKey;

    @Value("${app.jwt.AuthExpiration}")
    private long expirationTime;

    @Value("${app.jwt.refreshExpiration}")
    private long refreshExpirationTime;

    private static final String TOKEN_PREFIX = "Bearer ";

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

    public Optional<String> usernameFromToken(String token) {
        return usernameFromToken(token, false);
    }

    public Optional<String> usernameFromToken(String token, boolean isRefreshToken) {
        Optional<Claims> claims = extractClaims(token, isRefreshToken);
        String username = claims.map(Claims::getSubject).orElse(null);
        log.debug("Extracted username from {} token: {}", isRefreshToken ? "refresh" : "access", username);
        return Optional.ofNullable(username);
    }

    public boolean isTokenValid(String token) {
        return isTokenValid(token, false);
    }

    public boolean isTokenValid(String token, boolean isRefreshToken) {
        boolean valid = extractClaims(token, isRefreshToken).isPresent();
        log.debug("Token validity check ({}): {}", isRefreshToken ? "refresh" : "access", valid);
        return valid;
    }

    public Optional<Claims> extractClaims(String token) {
        return extractClaims(token, false);
    }

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

    private SecretKey getAccessSigningKey() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));
    }

    private SecretKey getRefreshSigningKey() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(refreshSecretKey));
    }

    public TokenPair generateTokenPair(Authentication authentication) {
        String accessToken = generateAccessToken(authentication);
        String refreshToken = generateRefreshToken(authentication);
        log.debug("Generated token pair for user '{}'", authentication.getName());
        return new TokenPair(accessToken, refreshToken);
    }
}