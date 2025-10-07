package com.sprintboot.webapp.plantilla.modules.logging.infrastructure.repository;

import com.sprintboot.webapp.plantilla.modules.logging.domain.RequestLog;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface RequestLogRepository extends JpaRepository<RequestLog, UUID> {
}
