package com.sprintboot.webapp.plantilla.modules.users.infrastructure.repository;

import com.sprintboot.webapp.plantilla.modules.users.domain.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByCode(String code);
}
