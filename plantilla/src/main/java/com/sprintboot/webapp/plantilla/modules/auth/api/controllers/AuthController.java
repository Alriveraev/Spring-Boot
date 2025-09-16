package com.sprintboot.webapp.plantilla.modules.auth.api.controllers;


import com.sprintboot.webapp.plantilla.modules.auth.api.dto.*;
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
    private final RequestLogService requestLog;

    @Operation(summary = "Login (público)")
    @PostMapping("/login")
    public ResponseEntity<AuthTokensResponse> login(@Valid @RequestBody AuthLoginRequest req, HttpServletRequest http) {
        final String path = "/api/auth/login";
        final String ip = http.getRemoteAddr();
        final String ua = http.getHeader("User-Agent");

        try {
            AuthTokensResponse tokens = auth.login(req, ip, ua);

            // En nuestro AuthService el subject del JWT es userId; podemos extraerlo parseando el access,
            // pero más eficiente: AuthService puede retornar también el userId. Para no tocar su firma,
            // registramos email (si quieres userId, ver alternativa más abajo).
            requestLog.log(null, req.email(), "POST", path, 200, true, ip, ua);

            return ResponseEntity.ok(tokens);
        } catch (BadCredentialsException ex) {
            // (Opcional) log de intento fallido:
            requestLog.log(null, req.email(), "POST", path, 401, false, ip, ua);
            throw ex;
        }
    }

    @Operation(summary = "Refresh token (público con refresh)")
    @PostMapping("/refresh")
    public ResponseEntity<AuthTokensResponse> refresh(@Valid @RequestBody AuthRefreshRequest req, HttpServletRequest http) {
        String ip = http.getRemoteAddr();
        String ua = http.getHeader("User-Agent");
        return ResponseEntity.ok(auth.refresh(req, ip, ua));
    }

    @Operation(summary = "Logout (público con refresh)")
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@Valid @RequestBody AuthLogoutRequest req) {
        auth.logout(req);
        return ResponseEntity.noContent().build();
    }
}
