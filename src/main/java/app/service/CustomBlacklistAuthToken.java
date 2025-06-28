package app.service;

import app.model.AuthTokenBlackList;
import app.repository.AuthTokenBlackListRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Date;


@Slf4j
@Service
public class CustomBlacklistAuthToken {
    private final AuthTokenBlackListRepository tokenBlackListRepository;
    private final JwtService jwtService;

    public CustomBlacklistAuthToken(AuthTokenBlackListRepository tokenBlackListRepository, JwtService jwtService) {
        this.tokenBlackListRepository = tokenBlackListRepository;
        this.jwtService = jwtService;
    }


    void blacklistToken(String authToken){
        log.debug("Attempting to blacklist auth token");
        try {
            String tokenId = jwtService.extractJti(authToken);
            String username = jwtService.extractUsername(authToken);
            Date expiration = jwtService.extractExpiration(authToken).orElse(null);
            log.info("Blacklisting auth token for user: {}, token ID: {}, expires at: {}", username, tokenId, expiration);
            if (expiration == null) return;
            AuthTokenBlackList blackListedToken = new AuthTokenBlackList(tokenId, username, expiration.toInstant());
            this.tokenBlackListRepository.save(blackListedToken);
            log.debug("Successfully blacklisted auth token for user: {}", username);
        } catch (Exception e) {
            log.error("Error while blacklisting auth token", e);
            throw e;
        }





    }

    boolean isTokenBlacklisted(String jti){
        return this.tokenBlackListRepository.existsByJti(jti);
    }


    void cleanupExpiredTokens(){
        this.tokenBlackListRepository.deleteExpiredTokens(Instant.now());

    }


    void removeUserTokens(String username){
        this.tokenBlackListRepository.deleteByUsername(username);

    }
}
