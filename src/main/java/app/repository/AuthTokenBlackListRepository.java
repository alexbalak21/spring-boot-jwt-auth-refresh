package app.repository;

import app.model.AuthTokenBlackList;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;

@Repository
public interface AuthTokenBlackListRepository extends JpaRepository<AuthTokenBlackList, Long> {
    
    boolean existsByJti(String jti);
    
    Optional<AuthTokenBlackList> findByJti(String jti);
    
    @Modifying
    @Query("DELETE FROM AuthTokenBlackList t WHERE t.expiresAt < :now")
    int deleteExpiredTokens(@Param("now") Instant now);
    
    @Modifying
    @Query("DELETE FROM AuthTokenBlackList t WHERE t.username = :username")
    void deleteByUsername(@Param("username") String username);
}
