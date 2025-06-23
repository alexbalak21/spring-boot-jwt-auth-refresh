package app.service.impl;

import app.model.AuthTokenBlackList;
import app.repository.AuthTokenBlackListRepository;
import app.service.AuthTokenBlackListService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

/**
 * Implementation of the AuthTokenBlackListService for JWT token blacklisting.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthTokenBlackListServiceImpl implements AuthTokenBlackListService {

    private final AuthTokenBlackListRepository tokenBlackListRepository;

    @Override
    @Transactional
    public void blacklistToken(String jti, String username, Instant expiresAt) {
        if (tokenBlackListRepository.existsByJti(jti)) {
            log.debug("Token with jti: {} is already blacklisted", jti);
            return;
        }

        AuthTokenBlackList blackListedToken = new AuthTokenBlackList();
        blackListedToken.setJti(jti);
        blackListedToken.setUsername(username);
        blackListedToken.setExpiresAt(expiresAt);
        
        tokenBlackListRepository.save(blackListedToken);
        log.debug("Token with jti: {} has been blacklisted for user: {}", jti, username);
    }

    @Override
    @Transactional(readOnly = true)
    public boolean isTokenBlacklisted(String jti) {
        return tokenBlackListRepository.existsByJti(jti);
    }

    @Override
    @Transactional
    @Scheduled(cron = "${app.token-cleanup.cron:0 0 0 * * *}") // Default: run daily at midnight
    public void cleanupExpiredTokens() {
        Instant now = Instant.now();
        int deleted = tokenBlackListRepository.deleteExpiredTokens(now);
        log.info("Cleaned up {} expired tokens from blacklist", deleted);
    }

    @Override
    @Transactional
    public void removeUserTokens(String username) {
        tokenBlackListRepository.deleteByUsername(username);
        log.debug("Removed all blacklisted tokens for user: {}", username);
    }
}
