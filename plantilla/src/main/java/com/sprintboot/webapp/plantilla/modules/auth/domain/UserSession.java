package com.sprintboot.webapp.plantilla.modules.auth.domain;

import com.sprintboot.webapp.plantilla.modules.users.domain.User;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.UuidGenerator;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "user_sessions", uniqueConstraints = @UniqueConstraint(name = "uk_user_sessions_refresh", columnNames = "refresh_token_id"))
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserSession {
    @Id
    @UuidGenerator  // ✅ UUID
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "refresh_token_id", nullable = false, length = 64)
    private String refreshTokenId;
    @Column(name = "refresh_hash", nullable = false, length = 255)
    private String refreshHash;
    @Column(name = "access_jti", length = 64)
    private String accessJti;

    @Column(name = "issued_at", nullable = false)
    @Builder.Default
    private Instant issuedAt = Instant.now();

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;
    @Column(name = "revoked_at")
    private Instant revokedAt;
    private String revokedReason;

    @Column(name = "ip_address", length = 45)
    private String ipAddress;
    @Column(name = "user_agent", length = 512)
    private String userAgent;
    @Column(name = "last_seen_at")
    private Instant lastSeenAt;

    public void revoke(String reason) {
        this.revokedAt = Instant.now();
        this.revokedReason = reason;
    }

    public void touch() {
        this.lastSeenAt = Instant.now();
    }
}
