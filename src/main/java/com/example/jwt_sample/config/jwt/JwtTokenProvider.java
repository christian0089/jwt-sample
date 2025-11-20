package com.example.jwt_sample.config.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.*;
import java.util.stream.Collectors;

@Component
public class JwtTokenProvider {

    private static final String CLAIM_ROLES = "roles";
    private static final String CLAIM_TYPE  = "type";   // ✅ 토큰 타입 구분용

    private final JwtProperties jwtProperties;
    private Key signingKey;

    public JwtTokenProvider(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
    }

    @PostConstruct
    public void init() {
        this.signingKey = Keys.hmacShaKeyFor(
                jwtProperties.getSecretKey().getBytes(StandardCharsets.UTF_8)
        );
    }

    // ✅ 공통 토큰 생성 로직
    private String createToken(String username,
                               String rolesString,
                               long validitySeconds,
                               String tokenType) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + validitySeconds * 1000);

        JwtBuilder builder = Jwts.builder()
                .setSubject(username)
                .setIssuer(jwtProperties.getIssuer())
                .setIssuedAt(now)
                .setExpiration(expiry)
                .claim(CLAIM_TYPE, tokenType);

        if (rolesString != null && !rolesString.isBlank()) {
            builder.claim(CLAIM_ROLES, rolesString);
        }

        return builder
                .signWith(signingKey, SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Access Token 생성 (roles 포함)
     */
    public String createAccessToken(String username, Collection<? extends GrantedAuthority> roles) {

        String rolesString = roles.stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        return createToken(
                username,
                rolesString,
                jwtProperties.getAccessTokenValiditySeconds(),
                "access"
        );
    }

    /**
     * Refresh Token 생성 (roles 없어도 됨, 여기서는 생략)
     */
    public String createRefreshToken(String username) {
        return createToken(
                username,
                null,
                jwtProperties.getRefreshTokenValiditySeconds(),
                "refresh"
        );
    }

    public boolean validateToken(String token) {
        try {
            Claims claims = getClaims(token);
            return !claims.getExpiration().before(new Date());
        } catch (ExpiredJwtException e) {
            System.out.println("JWT expired");
            return false;
        } catch (JwtException | IllegalArgumentException e) {
            System.out.println("JWT invalid: " + e.getMessage());
            return false;
        }
    }

    public boolean isRefreshToken(String token) {
        Claims claims = getClaims(token);
        String type = claims.get(CLAIM_TYPE, String.class);
        return "refresh".equals(type);
    }

    public String getUsername(String token) {
        return getClaims(token).getSubject();
    }

    public Authentication getAuthentication(String token) {
        Claims claims = getClaims(token);
        String username = claims.getSubject();
        String rolesString = claims.get(CLAIM_ROLES, String.class);

        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        if (rolesString != null && !rolesString.isBlank()) {
            authorities = Arrays.stream(rolesString.split(","))
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
        }

        org.springframework.security.core.userdetails.User principal =
                new org.springframework.security.core.userdetails.User(
                        username,
                        "",
                        authorities
                );

        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }

    private Claims getClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}