package com.sprintboot.webapp.plantilla.modules.logging.application;

import com.sprintboot.webapp.plantilla.modules.logging.domain.RequestLog;
import com.sprintboot.webapp.plantilla.modules.logging.infrastructure.repository.RequestLogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RequestLogService {

    private final RequestLogRepository repo;

    @Transactional
    public void log(UUID userId, String email, String method, String path,  // ✅ UUID en lugar de Long
                    int statusCode, boolean success, String ip, String ua) {
        RequestLog log = RequestLog.builder()
                .userId(userId)
                .email(email)
                .method(method)
                .path(path)
                .statusCode(statusCode)
                .success(success)
                .ipAddress(ip)
                .userAgent(ua)
                .build();
        repo.save(log);
    }
}