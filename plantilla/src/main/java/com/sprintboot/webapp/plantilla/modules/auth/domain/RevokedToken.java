package com.sprintboot.webapp.plantilla.modules.auth.domain;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Table(name = "revoked_tokens", uniqueConstraints = @UniqueConstraint(name = "uk_revoked_tokens_jti", columnNames = "jti"))
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RevokedToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 64)
    private String jti;
    @Column(nullable = false)
    @Builder.Default
    private Instant revokedAt = Instant.now();
    private String reason;
}
