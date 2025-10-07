package com.sprintboot.webapp.plantilla.modules.auth.api.controllers;

import com.sprintboot.webapp.plantilla.api.dto.ApiResponse;
import com.sprintboot.webapp.plantilla.modules.auth.api.dto.AuthLoginRequest;
import com.sprintboot.webapp.plantilla.modules.auth.api.dto.AuthLogoutRequest;
import com.sprintboot.webapp.plantilla.modules.auth.api.dto.AuthRefreshRequest;
import com.sprintboot.webapp.plantilla.modules.auth.api.dto.AuthTokensResponse;
import com.sprintboot.webapp.plantilla.modules.auth.application.AuthService;
import com.sprintboot.webapp.plantilla.modules.logging.application.RequestLogService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.*;

@Slf4j
@Tag(name = "Auth")
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService auth;

    @Operation(summary = "Login (público)")
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<AuthTokensResponse>> login(@Valid @RequestBody AuthLoginRequest req, HttpServletRequest http) {

        final String path = "/api/auth/login";
        final String ip = http.getRemoteAddr();
        final String ua = http.getHeader("User-Agent");

        log.info("POST {} email={} ip={}", path, req.email(), ip);

        AuthTokensResponse tokens = auth.login(req, ip, ua);
        return ResponseEntity.ok(ApiResponse.success("Login exitoso", tokens));
    }

    @Operation(summary = "Refresh token (público con refresh)")
    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<AuthTokensResponse>> refresh(@Valid @RequestBody AuthRefreshRequest req, HttpServletRequest http) {

        final String ip = http.getRemoteAddr();
        final String ua = http.getHeader("User-Agent");

        log.info("POST /api/auth/refresh ip={}", ip);

        AuthTokensResponse tokens = auth.refresh(req, ip, ua);

        return ResponseEntity.ok(ApiResponse.success("Token renovado exitosamente", tokens));
    }

    @Operation(summary = "Logout (público con refresh)")
    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(@Valid @RequestBody AuthLogoutRequest req) {
        log.info("POST /api/auth/logout");

        auth.logout(req);

        return ResponseEntity.ok(ApiResponse.message("Sesión cerrada exitosamente"));
    }
}