package app.repository;

import app.model.RefreshTokenBlacklist;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;

@Repository
public interface RefreshTokenBlacklistRepository extends JpaRepository<RefreshTokenBlacklist, Long> {
    
    boolean existsByTokenId(String tokenId);
    
    Optional<RefreshTokenBlacklist> findByTokenId(String tokenId);
    
    @Modifying
    @Query("DELETE FROM RefreshTokenBlacklist t WHERE t.expiresAt < :now")
    int deleteExpiredTokens(@Param("now") Instant now);
    
    @Modifying
    @Query("DELETE FROM RefreshTokenBlacklist t WHERE t.username = :username")
    void deleteByUsername(@Param("username") String username);
    
    @Modifying
    @Query("DELETE FROM RefreshTokenBlacklist t WHERE t.username = :username AND t.tokenId = :tokenId")
    void deleteByUsernameAndTokenId(@Param("username") String username, @Param("tokenId") String tokenId);

}
