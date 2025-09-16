package com.sprintboot.webapp.plantilla.modules.auth.infrastructure;

import com.sprintboot.webapp.plantilla.modules.auth.application.JwtService;
import com.sprintboot.webapp.plantilla.modules.auth.infrastructure.repository.RevokedTokenRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.*;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.*;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwt;
    private final RevokedTokenRepository revoked;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7);
            try {
                Jws<Claims> jws = jwt.parse(token);
                String jti = jws.getBody().getId();
                if (jti != null && revoked.findByJti(jti).isPresent())
                    throw new BadCredentialsException("Token revoked");

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
                SecurityContextHolder.clearContext();
                throw new BadCredentialsException("Invalid JWT", e);
            }
        }

        chain.doFilter(request, response);
    }
}
