package app.service;

import app.model.RefreshTokenBlacklist;
import app.repository.RefreshTokenBlacklistRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Date;
import java.util.Objects;

@Slf4j
@Service
public class CustomBlacklistRefreshToken {
    private final RefreshTokenBlacklistRepository refreshTokenBlacklistRepository;
    private final JwtService jwtService;


    public CustomBlacklistRefreshToken(RefreshTokenBlacklistRepository refreshTokenBlacklistRepository, JwtService jwtService) {
        this.refreshTokenBlacklistRepository = refreshTokenBlacklistRepository;
        this.jwtService = jwtService;
    }


     public void blackListToken(String refreshToken) {
        log.debug("Attempting to blacklist refresh token");
        try {
            String tokenId = jwtService.extractJti(refreshToken,true);
            String username = jwtService.extractUsername(refreshToken, true);
            Date expiration = jwtService.extractExpiration(refreshToken, true).orElse(null);
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
        return refreshTokenBlacklistRepository.existsByTokenId(tokenId);
    }

    void cleanupExpiredTokens(){
        this.refreshTokenBlacklistRepository.deleteExpiredTokens(Instant.now());
    }

    void removeUserTokens(String username){
        this.refreshTokenBlacklistRepository.deleteByUsername(username);
    }

}