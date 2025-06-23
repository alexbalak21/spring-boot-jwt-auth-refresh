package app.service.impl;

import app.model.RefreshTokenBlacklist;
import app.repository.RefreshTokenBlacklistRepository;
import app.service.RefreshTokenBlacklistService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

/**
 * Implementation of the RefreshTokenBlacklistService for refresh token blacklisting.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RefreshTokenBlacklistServiceImpl implements RefreshTokenBlacklistService {

    private final RefreshTokenBlacklistRepository refreshTokenBlacklistRepository;

    @Override
    @Transactional
    public void blacklistToken(String tokenId, String username, Instant expiresAt) {
        if (refreshTokenBlacklistRepository.existsByTokenId(tokenId)) {
            log.debug("Refresh token with id: {} is already blacklisted", tokenId);
            return;
        }

        RefreshTokenBlacklist blacklistedToken = new RefreshTokenBlacklist();
        blacklistedToken.setTokenId(tokenId);
        blacklistedToken.setUsername(username);
        blacklistedToken.setExpiresAt(expiresAt);
        
        refreshTokenBlacklistRepository.save(blacklistedToken);
        log.debug("Refresh token with id: {} has been blacklisted for user: {}", tokenId, username);
    }

    @Override
    @Transactional(readOnly = true)
    public boolean isTokenBlacklisted(String tokenId) {
        return refreshTokenBlacklistRepository.existsByTokenId(tokenId);
    }

    @Override
    @Transactional
    @Scheduled(cron = "${app.refresh-token-cleanup.cron:0 0 0 * * *}") // Default: run daily at midnight
    public void cleanupExpiredTokens() {
        Instant now = Instant.now();
        int deleted = refreshTokenBlacklistRepository.deleteExpiredTokens(now);
        log.info("Cleaned up {} expired refresh tokens from blacklist", deleted);
    }

    @Override
    @Transactional
    public void removeUserTokens(String username) {
        refreshTokenBlacklistRepository.deleteByUsername(username);
        log.debug("Removed all blacklisted refresh tokens for user: {}", username);
    }

    @Override
    @Transactional
    public void removeToken(String username, String tokenId) {
        refreshTokenBlacklistRepository.deleteByUsernameAndTokenId(username, tokenId);
        log.debug("Removed refresh token with id: {} for user: {}", tokenId, username);
    }
}
