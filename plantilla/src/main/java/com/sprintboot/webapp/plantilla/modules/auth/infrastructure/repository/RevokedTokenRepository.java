package com.sprintboot.webapp.plantilla.modules.auth.infrastructure.repository;

import com.sprintboot.webapp.plantilla.modules.auth.domain.RevokedToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RevokedTokenRepository extends JpaRepository<RevokedToken, Long> {
    Optional<RevokedToken> findByJti(String jti);
}
