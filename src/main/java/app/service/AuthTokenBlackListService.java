package app.service;

import java.time.Instant;

/**
 * Service interface for token blacklist operations.
 */
public interface AuthTokenBlackListService {
    
    /**
     * Blacklist a JWT token.
     * @param jti The JWT ID to blacklist
     * @param username The username associated with the token
     * @param expiresAt When the token expires
     */
    void blacklistToken(String jti, String username, Instant expiresAt);
    
    /**
     * Check if a token is blacklisted.
     * @param jti The JWT ID to check
     * @return true if the token is blacklisted, false otherwise
     */
    boolean isTokenBlacklisted(String jti);
    
    /**
     * Remove all expired tokens from the blacklist.
     */
    void cleanupExpiredTokens();
    
    /**
     * Remove all tokens for a specific user.
     * @param username The username whose tokens should be removed
     */
    void removeUserTokens(String username);
}
