package app.service;

import java.time.Instant;

/**
 * Service interface for refresh token blacklist operations.
 */
public interface RefreshTokenBlacklistService {
    
    /**
     * Blacklist a refresh token.
     * @param tokenId The token ID to blacklist
     * @param username The username associated with the token
     * @param expiresAt When the token expires
     */
    void blacklistToken(String tokenId, String username, Instant expiresAt);
    
    /**
     * Check if a refresh token is blacklisted.
     * @param tokenId The token ID to check
     * @return true if the token is blacklisted, false otherwise
     */
    boolean isTokenBlacklisted(String tokenId);
    
    /**
     * Remove all expired refresh tokens from the blacklist.
     */
    void cleanupExpiredTokens();
    
    /**
     * Remove all refresh tokens for a specific user.
     * @param username The username whose refresh tokens should be removed
     */
    void removeUserTokens(String username);
    
    /**
     * Remove a specific refresh token for a user.
     * @param username The username
     * @param tokenId The token ID to remove
     */
    void removeToken(String username, String tokenId);
}
