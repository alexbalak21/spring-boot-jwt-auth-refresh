package app.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.Instant;

@Setter
@Getter
@Entity
@Table(name = "refresh_token_blacklist")
public class RefreshTokenBlacklist {
    // Getters and Setters
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false, unique = true)
    private String tokenId;
    
    @Column(nullable = false)
    private String username;
    
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();
    
    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;
    
    @Column(name = "reason")
    private String reason;
    
    @Column(name = "ip_address")
    private String ipAddress;
    
    @Column(name = "user_agent")
    private String userAgent;
    
    public RefreshTokenBlacklist() {
    }
    
    public RefreshTokenBlacklist(String tokenId, String username, Instant expiresAt) {
        this.tokenId = tokenId;
        this.username = username;
        this.expiresAt = expiresAt;
    }
    
    public RefreshTokenBlacklist(String tokenId, String username, Instant expiresAt, 
                               String reason, String ipAddress, String userAgent) {
        this.tokenId = tokenId;
        this.username = username;
        this.expiresAt = expiresAt;
        this.reason = reason;
        this.ipAddress = ipAddress;
        this.userAgent = userAgent;
    }

}
