package app.service;

import app.model.RefreshTokenBlacklist;
import app.repository.RefreshTokenBlacklistRepository;
import lombok.extern.slf4j.Slf4j;

import java.time.Instant;
import java.util.Date;
import java.util.Objects;

@Slf4j
public class CustomBlacklistRefreshToken {
    private final RefreshTokenBlacklistRepository refreshTokenBlacklistRepository;
    private final JwtService jwtService;


    public CustomBlacklistRefreshToken(RefreshTokenBlacklistRepository refreshTokenBlacklistRepository, JwtService jwtService, RefreshTokenBlacklist refreshTokenBlacklist) {
        this.refreshTokenBlacklistRepository = refreshTokenBlacklistRepository;
        this.jwtService = jwtService;
    }

    void blacklistRefreshToken(String refreshToken) {
        log.debug("Attempting to blacklist refresh token");
        try {
            String tokenId = jwtService.extractJti(refreshToken);
            String username = jwtService.extractUsername(refreshToken);
            Date expiration = jwtService.extractExpiration(refreshToken).orElse(null);
            log.info("Blacklisting refresh token for user: {}, token ID: {}, expires at: {}", username, tokenId, expiration);
            if (expiration == null) return;
            RefreshTokenBlacklist refreshTokenBlacklist = new RefreshTokenBlacklist(tokenId, username, expiration.toInstant());
            this.refreshTokenBlacklistRepository.save(refreshTokenBlacklist);
            log.debug("Successfully blacklisted refresh token for user: {}", username);
        } catch (Exception e) {
            log.error("Error while blacklisting refresh token", e);
            throw e;
        }
    }

    boolean isTokenBlacklisted(String tokenId){
        return Objects.nonNull(this.refreshTokenBlacklistRepository.findByTokenId(tokenId).orElse(null));
    }

    void cleanupExpiredTokens(){
        this.refreshTokenBlacklistRepository.deleteExpiredTokens(Instant.now());
    }

    void removeUserTokens(String username){
        this.refreshTokenBlacklistRepository.deleteByUsername(username);
    }

}