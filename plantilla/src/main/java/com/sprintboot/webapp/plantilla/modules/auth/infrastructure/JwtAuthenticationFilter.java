package com.sprintboot.webapp.plantilla.modules.auth.infrastructure;

import com.sprintboot.webapp.plantilla.modules.auth.application.JwtService;
import com.sprintboot.webapp.plantilla.modules.auth.infrastructure.repository.RevokedTokenRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.*;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwt;
    private final RevokedTokenRepository revoked;

    // ⭐ NUEVO: Lista de rutas públicas que NO necesitan JWT
    private static final List<String> PUBLIC_PATHS = List.of(
            "/api/auth/login",
            "/api/auth/refresh",
            "/api/auth/logout",
            "/v3/api-docs",
            "/swagger-ui",
            "/docs"
    );

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String path = request.getRequestURI();

        // ⭐ NUEVO: Si es ruta pública, saltar validación JWT
        if (isPublicPath(path)) {
            log.debug("Ruta pública detectada: {} - Saltando validación JWT", path);
            chain.doFilter(request, response);
            return;
        }

        String header = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7);
            try {
                Jws<Claims> jws = jwt.parse(token);
                String jti = jws.getBody().getId();

                // Si el token está revocado, no autenticar
                if (jti != null && revoked.findByJti(jti).isPresent()) {
                    log.warn("Token revocado: jti={}", jti);
                    SecurityContextHolder.clearContext();
                    chain.doFilter(request, response);
                    return;
                }

                String userId = jws.getBody().getSubject();
                @SuppressWarnings("unchecked")
                List<String> roles = (List<String>) jws.getBody().get("roles");
                if (roles == null) roles = List.of();

                List<GrantedAuthority> auths = roles.stream()
                        .map(r -> new SimpleGrantedAuthority("ROLE_" + r))
                        .collect(Collectors.toList());

                Authentication auth = new UsernamePasswordAuthenticationToken(userId, null, auths);
                SecurityContextHolder.getContext().setAuthentication(auth);

            } catch (Exception e) {
                log.debug("JWT inválido o expirado: {}", e.getMessage());
                SecurityContextHolder.clearContext();
            }
        }

        chain.doFilter(request, response);
    }

    // ⭐ NUEVO: Método helper para verificar rutas públicas
    private boolean isPublicPath(String path) {
        return PUBLIC_PATHS.stream().anyMatch(path::startsWith);
    }
}