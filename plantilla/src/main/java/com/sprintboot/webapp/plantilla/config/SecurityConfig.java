package com.sprintboot.webapp.plantilla.config;

import com.sprintboot.webapp.plantilla.modules.auth.application.JwtService;
import com.sprintboot.webapp.plantilla.modules.auth.infrastructure.JwtAuthenticationFilter;
import com.sprintboot.webapp.plantilla.modules.auth.infrastructure.repository.RevokedTokenRepository;
import com.sprintboot.webapp.plantilla.modules.logging.application.RequestLogService;
import com.sprintboot.webapp.plantilla.modules.logging.infrastructure.RequestLoggingFilter;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.*;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.*;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.*;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.time.Instant;
import java.util.Arrays;

@Configuration
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig {

    private static final String[] SWAGGER_WHITELIST = {
            "/v3/api-docs/**", "/swagger-ui.html", "/swagger-ui/**", "/docs"
    };

    private final JwtService jwtService;
    private final RevokedTokenRepository revokedRepo;
    private final Environment env;
    private final RequestLogService requestLogService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        boolean isDev = Arrays.asList(env.getActiveProfiles()).contains("dev");

        http.csrf(csrf -> csrf.disable())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers("/api/auth/login", "/api/auth/refresh", "/api/auth/logout").permitAll();
                    if (isDev) auth.requestMatchers(SWAGGER_WHITELIST).permitAll();
                    auth.anyRequest().authenticated();
                })
                // ⭐ NUEVO: Manejo de excepciones
                .exceptionHandling(ex -> ex
                        // 401: Sin autenticación (sin token o token inválido)
                        .authenticationEntryPoint((request, response, authException) -> {
                            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                            response.setContentType("application/json;charset=UTF-8");
                            response.getWriter().write(String.format("""
                                    {
                                        "timestamp": "%s",
                                        "status": 401,
                                        "error": "Unauthorized",
                                        "message": "Se requiere autenticación. Por favor, proporciona un token válido.",
                                        "path": "%s"
                                    }
                                    """, Instant.now(), request.getRequestURI()));
                        })
                        // 403: Con autenticación pero sin permisos
                        .accessDeniedHandler((request, response, accessDeniedException) -> {
                            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                            response.setContentType("application/json;charset=UTF-8");
                            response.getWriter().write(String.format("""
                                    {
                                        "timestamp": "%s",
                                        "status": 403,
                                        "error": "Forbidden",
                                        "message": "No tienes permisos suficientes para acceder a este recurso.",
                                        "path": "%s"
                                    }
                                    """, Instant.now(), request.getRequestURI()));
                        })
                )
                .addFilterBefore(new JwtAuthenticationFilter(jwtService, revokedRepo),
                        UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(new RequestLoggingFilter(
                        requestLogService,
                        buildPublicPatterns(isDev)
                ), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    private java.util.List<String> buildPublicPatterns(boolean isDev) {
        java.util.List<String> patterns = new java.util.ArrayList<>();
        patterns.add("/api/auth/login");
        patterns.add("/api/auth/refresh");
        patterns.add("/api/auth/logout");
        if (isDev) {
            patterns.add("/v3/api-docs/**");
            patterns.add("/swagger-ui.html");
            patterns.add("/swagger-ui/**");
            patterns.add("/docs");
        }
        return patterns;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration cfg) throws Exception {
        return cfg.getAuthenticationManager();
    }
}