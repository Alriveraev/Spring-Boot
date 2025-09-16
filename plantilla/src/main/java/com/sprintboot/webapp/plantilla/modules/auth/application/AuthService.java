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

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository users;
    private final UserSessionRepository sessions;
    private final RevokedTokenRepository revoked;
    private final PasswordEncoder encoder;
    private final JwtService jwt;

    private static final long REFRESH_DAYS = 30;
    private final SecureRandom random = new SecureRandom();

    public AuthTokensResponse login(AuthLoginRequest req, String ip, String ua) {
        log.info("POST /api/auth/login email={} ip={}", req.email(), ip);
        User u = users.findByEmail(req.email().trim().toLowerCase())
                .orElseThrow(() -> new BadCredentialsException("Invalid credentials"));
        if (!u.isEnabled() || u.isLocked()) throw new BadCredentialsException("User disabled or locked");
        if (!encoder.matches(req.password(), u.getPasswordHash()))
            throw new BadCredentialsException("Invalid credentials");

        Set<String> roleCodes = u.getRoles().stream().map(Role::getCode).collect(Collectors.toSet());
        Map<String, Object> claims = new HashMap<>();
        claims.put("email", u.getEmail());
        claims.put("roles", roleCodes);

        String accessJti = UUID.randomUUID().toString();
        String access = jwt.generateAccess(u.getId().toString(), accessJti, claims);

        String refreshId = UUID.randomUUID().toString();
        String refreshSecret = generateTokenSecret(64);
        String refreshToken = refreshId + "." + refreshSecret;
        String refreshHash = encoder.encode(refreshToken);
        Instant refreshExp = Instant.now().plus(REFRESH_DAYS, ChronoUnit.DAYS);

        UserSession sess = UserSession.builder()
                .user(u).refreshTokenId(refreshId).refreshHash(refreshHash)
                .accessJti(accessJti).expiresAt(refreshExp).ipAddress(ip).userAgent(ua).build();
        sessions.save(sess);

        u.setLastLoginAt(Instant.now());

        return new AuthTokensResponse(
                access, jwt.getAccessSeconds(),
                refreshToken, REFRESH_DAYS * 24 * 3600,
                "Bearer"
        );
    }

    public AuthTokensResponse refresh(AuthRefreshRequest req, String ip, String ua) {
        log.info("POST /api/auth/refresh ip={}", ip);
        String token = req.refreshToken().trim();
        String[] parts = token.split("\\.", 2);
        if (parts.length != 2) throw new BadCredentialsException("Malformed refresh token");
        String id = parts[0];
        String secret = parts[1];

        UserSession sess = sessions.findByRefreshTokenId(id)
                .orElseThrow(() -> new BadCredentialsException("Invalid refresh token"));

        if (sess.getRevokedAt() != null || sess.getExpiresAt().isBefore(Instant.now()))
            throw new BadCredentialsException("Refresh token expired or revoked");

        if (!encoder.matches(id + "." + secret, sess.getRefreshHash()))
            throw new BadCredentialsException("Invalid refresh token");

        User u = sess.getUser();

        if (sess.getAccessJti() != null) {
            revoked.save(RevokedToken.builder().jti(sess.getAccessJti()).reason("refresh rotation").build());
        }

        sess.revoke("rotated");
        sessions.save(sess);

        Set<String> roleCodes = u.getRoles().stream().map(Role::getCode).collect(Collectors.toSet());
        Map<String, Object> claims = new HashMap<>();
        claims.put("email", u.getEmail());
        claims.put("roles", roleCodes);

        String newJti = UUID.randomUUID().toString();
        String access = jwt.generateAccess(u.getId().toString(), newJti, claims);

        String newId = UUID.randomUUID().toString();
        String newSecret = generateTokenSecret(64);
        String newRefresh = newId + "." + newSecret;
        String newHash = encoder.encode(newRefresh);
        Instant newExp = Instant.now().plus(REFRESH_DAYS, ChronoUnit.DAYS);

        UserSession newSess = UserSession.builder()
                .user(u).refreshTokenId(newId).refreshHash(newHash)
                .accessJti(newJti).expiresAt(newExp).ipAddress(ip).userAgent(ua).build();
        sessions.save(newSess);

        return new AuthTokensResponse(
                access, jwt.getAccessSeconds(),
                newRefresh, REFRESH_DAYS * 24 * 3600,
                "Bearer"
        );
    }

    public void logout(AuthLogoutRequest req) {
        log.info("POST /api/auth/logout");
        String token = req.refreshToken().trim();
        String[] parts = token.split("\\.", 2);
        if (parts.length != 2) return;
        String id = parts[0];
        String secret = parts[1];

        sessions.findByRefreshTokenId(id).ifPresent(sess -> {
            if (sess.getRevokedAt() == null && encoder.matches(id + "." + secret, sess.getRefreshHash())) {
                sess.revoke("logout");
                sessions.save(sess);
                if (sess.getAccessJti() != null)
                    revoked.save(RevokedToken.builder().jti(sess.getAccessJti()).reason("logout").build());
            }
        });
    }

    private String generateTokenSecret(int bytes) {
        byte[] buf = new byte[bytes];
        random.nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }
}
