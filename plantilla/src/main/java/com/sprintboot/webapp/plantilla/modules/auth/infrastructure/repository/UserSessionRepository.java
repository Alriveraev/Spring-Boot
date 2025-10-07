package com.sprintboot.webapp.plantilla.modules.auth.infrastructure.repository;

import com.sprintboot.webapp.plantilla.modules.auth.domain.UserSession;
import com.sprintboot.webapp.plantilla.modules.users.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public interface UserSessionRepository extends JpaRepository<UserSession, UUID> {
    Optional<UserSession> findByRefreshTokenId(String refreshTokenId);

    long deleteByUserAndExpiresAtBefore(User user, Instant before);
}
