package com.sprintboot.webapp.plantilla.modules.logging.infrastructure;

import com.sprintboot.webapp.plantilla.modules.logging.application.RequestLogService;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpMethod;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@RequiredArgsConstructor
public class RequestLoggingFilter extends OncePerRequestFilter {

    private final RequestLogService requestLogService;
    private final List<String> publicPatterns;  // mismas rutas públicas que en SecurityConfig
    private final AntPathMatcher matcher = new AntPathMatcher();

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        // no filtrar login/refresh/logout y swagger (públicos)
        for (String p : publicPatterns) {
            if (matcher.match(p, path)) return true;
        }
        return false;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        // Deja pasar y captura el status al final
        chain.doFilter(request, response);

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        boolean authenticated = auth != null && auth.isAuthenticated();

        if (authenticated) {
            // En nuestro JwtAuthenticationFilter seteamos principal = subject (userId)
            Long userId = null;
            try {
                userId = Long.valueOf(auth.getName());
            } catch (NumberFormatException ignored) {
            }

            String method = request.getMethod();
            String path = request.getRequestURI();
            int status = response.getStatus();
            boolean success = status >= 200 && status < 400;
            String ip = request.getRemoteAddr();
            String ua = request.getHeader("User-Agent");

            // Guardar log (email no disponible aquí sin parsear el JWT otra vez; no es necesario)
            requestLogService.log(userId, null, method, path, status, success, ip, ua);
        }
    }
}
