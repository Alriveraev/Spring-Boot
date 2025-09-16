package com.sprintboot.webapp.plantilla.modules.logging.domain;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Table(name = "request_logs")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RequestLog {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private Long userId;
    @Column(length = 320)
    private String email;

    @Column(nullable = false, length = 10)
    private String method;
    @Column(nullable = false, length = 512)
    private String path;

    @Column(nullable = false)
    private int statusCode;
    @Column(nullable = false)
    private boolean success;

    @Column(length = 45)
    private String ipAddress;
    @Column(length = 512)
    private String userAgent;

    @Column(nullable = false)
    @Builder.Default
    private Instant occurredAt = Instant.now();
}
