package com.sprintboot.webapp.plantilla.modules.auth.application;

import com.sprintboot.webapp.plantilla.modules.auth.api.dto.*;
import com.sprintboot.webapp.plantilla.modules.auth.domain.RevokedToken;
import com.sprintboot.webapp.plantilla.modules.auth.domain.UserSession;
import com.sprintboot.webapp.plantilla.modules.auth.infrastructure.repository.RevokedTokenRepository;
import com.sprintboot.webapp.plantilla.modules.auth.infrastructure.repository.UserSessionRepository;
import com.sprintboot.webapp.plantilla.modules.users.domain.Role;
import com.sprintboot.webapp.plantilla.modules.users.domain.User;
import com.sprintboot.webapp.plantilla.modules.users.infrastructure.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository users;
    private final UserSessionRepository sessions;
    private final RevokedTokenRepository revoked;
    private final PasswordEncoder encoder;
    private final JwtService jwt;

    private static final long REFRESH_DAYS = 30;
    private static final int TOKEN_SECRET_BYTES = 64;
    private final SecureRandom random = new SecureRandom();

    @Transactional
    public AuthTokensResponse login(AuthLoginRequest req, String ip, String ua) {
        log.debug("AuthService.login email={}", req.email());

        // Buscar usuario
        String email = req.email().trim().toLowerCase();
        User user = users.findByEmail(email)
                .orElseThrow(() -> new BadCredentialsException("Credenciales inválidas"));

        // Validar estado del usuario
        if (!user.isEnabled() || user.isLocked()) {
            throw new BadCredentialsException("Usuario deshabilitado o bloqueado");
        }

        // Validar contraseña
        if (!encoder.matches(req.password(), user.getPasswordHash())) {
            throw new BadCredentialsException("Credenciales inválidas");
        }

        // Construir claims del JWT
        Set<String> roleCodes = user.getRoles().stream()
                .map(Role::getCode)
                .collect(Collectors.toSet());

        Map<String, Object> claims = new HashMap<>();
        claims.put("email", user.getEmail());
        claims.put("roles", roleCodes);

        // Generar access token
        String accessJti = UUID.randomUUID().toString();
        String accessToken = jwt.generateAccess(user.getId().toString(), accessJti, claims);

        // Generar refresh token
        String refreshId = UUID.randomUUID().toString();
        String refreshSecret = generateTokenSecret(TOKEN_SECRET_BYTES);
        String refreshToken = refreshId + "." + refreshSecret;
        String refreshHash = hashRefreshToken(refreshToken);
        Instant refreshExpiration = Instant.now().plus(REFRESH_DAYS, ChronoUnit.DAYS);

        // Guardar sesión
        UserSession session = UserSession.builder()
                .user(user)
                .refreshTokenId(refreshId)
                .refreshHash(refreshHash)
                .accessJti(accessJti)
                .expiresAt(refreshExpiration)
                .ipAddress(ip)
                .userAgent(ua)
                .build();
        sessions.save(session);

        // Actualizar último login
        user.setLastLoginAt(Instant.now());

        log.info("Login exitoso: userId={} email={}", user.getId(), user.getEmail());

        return new AuthTokensResponse(
                accessToken,
                jwt.getAccessSeconds(),
                refreshToken,
                REFRESH_DAYS * 24 * 3600,
                "Bearer"
        );
    }

    @Transactional
    public AuthTokensResponse refresh(AuthRefreshRequest req, String ip, String ua) {
        log.debug("AuthService.refresh");

        // Validar formato del refresh token
        String token = req.refreshToken().trim();
        String[] parts = token.split("\\.", 2);
        if (parts.length != 2) {
            throw new BadCredentialsException("Formato de refresh token inválido");
        }

        String refreshId = parts[0];
        String refreshSecret = parts[1];

        // Buscar sesión
        UserSession session = sessions.findByRefreshTokenId(refreshId)
                .orElseThrow(() -> new BadCredentialsException("Refresh token inválido"));

        // Validar estado de la sesión
        if (session.getRevokedAt() != null) {
            throw new BadCredentialsException("Refresh token revocado");
        }

        if (session.getExpiresAt().isBefore(Instant.now())) {
            throw new BadCredentialsException("Refresh token expirado");
        }

        // Validar hash del refresh token
        String expectedHash = hashRefreshToken(refreshId + "." + refreshSecret);
        if (!expectedHash.equals(session.getRefreshHash())) {
            throw new BadCredentialsException("Refresh token inválido");
        }

        User user = session.getUser();

        // Revocar el access token anterior
        if (session.getAccessJti() != null) {
            revoked.save(RevokedToken.builder()
                    .jti(session.getAccessJti())
                    .reason("refresh rotation")
                    .build());
        }

        // Revocar la sesión anterior
        session.revoke("rotated");
        sessions.save(session);

        // Construir nuevos claims
        Set<String> roleCodes = user.getRoles().stream()
                .map(Role::getCode)
                .collect(Collectors.toSet());

        Map<String, Object> claims = new HashMap<>();
        claims.put("email", user.getEmail());
        claims.put("roles", roleCodes);

        // Generar nuevo access token
        String newAccessJti = UUID.randomUUID().toString();
        String newAccessToken = jwt.generateAccess(user.getId().toString(), newAccessJti, claims);

        // Generar nuevo refresh token
        String newRefreshId = UUID.randomUUID().toString();
        String newRefreshSecret = generateTokenSecret(TOKEN_SECRET_BYTES);
        String newRefreshToken = newRefreshId + "." + newRefreshSecret;
        String newRefreshHash = hashRefreshToken(newRefreshToken);
        Instant newExpiration = Instant.now().plus(REFRESH_DAYS, ChronoUnit.DAYS);

        // Crear nueva sesión
        UserSession newSession = UserSession.builder()
                .user(user)
                .refreshTokenId(newRefreshId)
                .refreshHash(newRefreshHash)
                .accessJti(newAccessJti)
                .expiresAt(newExpiration)
                .ipAddress(ip)
                .userAgent(ua)
                .build();
        sessions.save(newSession);

        log.info("Token renovado: userId={}", user.getId());

        return new AuthTokensResponse(
                newAccessToken,
                jwt.getAccessSeconds(),
                newRefreshToken,
                REFRESH_DAYS * 24 * 3600,
                "Bearer"
        );
    }

    @Transactional
    public void logout(AuthLogoutRequest req) {
        log.debug("AuthService.logout");

        String token = req.refreshToken().trim();
        String[] parts = token.split("\\.", 2);
        if (parts.length != 2) {
            log.warn("Formato de refresh token inválido en logout");
            return;
        }

        String refreshId = parts[0];
        String refreshSecret = parts[1];

        sessions.findByRefreshTokenId(refreshId).ifPresent(session -> {
            String expectedHash = hashRefreshToken(refreshId + "." + refreshSecret);

            if (session.getRevokedAt() == null && expectedHash.equals(session.getRefreshHash())) {
                session.revoke("logout");
                sessions.save(session);

                if (session.getAccessJti() != null) {
                    revoked.save(RevokedToken.builder()
                            .jti(session.getAccessJti())
                            .reason("logout")
                            .build());
                }

                log.info("Logout exitoso: userId={}", session.getUser().getId());
            } else {
                log.warn("Intento de logout con token inválido o ya revocado");
            }
        });
    }

    // --- Métodos privados auxiliares ---

    private String hashRefreshToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Algoritmo SHA-256 no disponible", e);
        }
    }

    private String generateTokenSecret(int bytes) {
        byte[] buffer = new byte[bytes];
        random.nextBytes(buffer);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buffer);
    }
}