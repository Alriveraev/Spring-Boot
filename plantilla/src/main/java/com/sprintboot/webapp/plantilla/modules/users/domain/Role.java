package com.sprintboot.webapp.plantilla.modules.users.domain;


import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.UuidGenerator;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "roles", uniqueConstraints = @UniqueConstraint(name = "uk_roles_code", columnNames = "code"))
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Role {
    @Id
    @UuidGenerator  // ✅ UUID
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    @Column(nullable = false, length = 64)
    private String code;
    @Column(nullable = false, length = 128)
    private String name;
    @Column(length = 512)
    private String description;
    @Column(nullable = false)
    private boolean isSystem = false;

    @Column(nullable = false)
    private Instant createdAt = Instant.now();
    private String createdBy;
    private Instant updatedAt;
    private String updatedBy;
}
