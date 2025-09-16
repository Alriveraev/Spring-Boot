package com.sprintboot.webapp.plantilla.modules.auth.application;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Instant;
import java.util.*;

@Service
public class JwtService {

    private final Key key;
    private final String issuer;
    private final long accessMinutes;

    public JwtService(@Value("${app.jwt.secret}") String secret,
                      @Value("${app.jwt.issuer}") String issuer,
                      @Value("${app.jwt.expiration-minutes}") long accessMinutes) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.issuer = issuer;
        this.accessMinutes = accessMinutes;
    }

    public String generateAccess(String subject, String jti, Map<String, Object> claims) {
        Instant now = Instant.now(), exp = now.plusSeconds(accessMinutes * 60);
        return Jwts.builder()
                .setIssuer(issuer)
                .setSubject(subject)
                .setId(jti)
                .addClaims(claims)
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(exp))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public Jws<Claims> parse(String jwt) {
        return Jwts.parserBuilder()
                .requireIssuer(issuer)
                .setSigningKey(key)
                .build()
                .parseClaimsJws(jwt);
    }

    public long getAccessSeconds() {
        return accessMinutes * 60;
    }
}
