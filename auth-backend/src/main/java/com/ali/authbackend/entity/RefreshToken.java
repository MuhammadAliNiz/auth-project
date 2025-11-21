package com.ali.authbackend.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;
import java.util.UUID;

@Getter
@Setter
@Entity
@Table(name = "refresh_tokens", indexes = {
        @Index(name = "idx_refresh_token_jti", columnList = "jti"), // ADD THIS
        @Index(name = "idx_refresh_token_user_id", columnList = "user_id"),
        @Index(name = "idx_refresh_token_expiry", columnList = "expiryDate"),
        @Index(name = "idx_refresh_token_revoked", columnList = "revoked"),
        @Index(name = "idx_refresh_token_user_revoked", columnList = "user_id, revoked")
})
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, unique = true, updatable = false, length = 64)
    private String jti;

    @ManyToOne(optional = false, fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false, updatable = false)
    private User user;

    @Column(nullable = false)
    private Instant expiryDate;

    @Column(nullable = false)
    @Builder.Default
    private boolean revoked = false;

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    @Column
    private Instant lastUsedAt;

    @Column(length = 255)
    private String deviceInfo;

    @Column(length = 45) // IPv6 max length
    private String ipAddress;


    public boolean isValid() {
        return !revoked && !isExpired();
    }

    public boolean isExpired() {
        return expiryDate.isBefore(Instant.now());
    }

    public void revoke() {
        this.revoked = true;
    }

    public void updateLastUsed() {
        this.lastUsedAt = Instant.now();
    }
}