package com.example.jwt_sample.auth;

import com.example.jwt_sample.config.jwt.JwtTokenProvider;
import com.example.jwt_sample.config.jwt.RefreshTokenStore;
import lombok.Data;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenStore refreshTokenStore;
    private final UserDetailsService userDetailsService;

    public AuthController(AuthenticationManager authenticationManager,
                          JwtTokenProvider jwtTokenProvider,
                          RefreshTokenStore refreshTokenStore,
                          UserDetailsService userDetailsService) {
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;
        this.refreshTokenStore = refreshTokenStore;
        this.userDetailsService = userDetailsService;
    }

    // ✅ 1) 로그인: Access + Refresh 둘 다 반환
    @PostMapping("/login")
    public TokenResponse login(@RequestBody LoginRequest request) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getLoginId(),
                        request.getPassword()
                )
        );

        String username = request.getLoginId();

        String accessToken = jwtTokenProvider.createAccessToken(
                username,
                authentication.getAuthorities()
        );

        String refreshToken = jwtTokenProvider.createRefreshToken(username);

        // username 기준으로 Refresh Token 저장
        refreshTokenStore.save(username, refreshToken);

        return new TokenResponse(accessToken, refreshToken);
    }

    // ✅ 2) Refresh: Refresh Token으로 새 토큰 발급
    @PostMapping("/refresh")
    public TokenResponse refresh(@RequestBody RefreshRequest request) {

        String refreshToken = request.getRefreshToken();

        if (refreshToken == null || !jwtTokenProvider.validateToken(refreshToken)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid refresh token");
        }

        if (!jwtTokenProvider.isRefreshToken(refreshToken)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Not a refresh token");
        }

        String username = jwtTokenProvider.getUsername(refreshToken);

        if (!refreshTokenStore.isValid(username, refreshToken)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Refresh token not recognized");
        }

        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        String newAccessToken = jwtTokenProvider.createAccessToken(
                username,
                userDetails.getAuthorities()
        );
        String newRefreshToken = jwtTokenProvider.createRefreshToken(username);

        refreshTokenStore.save(username, newRefreshToken);

        return new TokenResponse(newAccessToken, newRefreshToken);
    }

    // ✅ 3) 로그아웃: 서버쪽 Refresh Token 제거
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestBody RefreshRequest request) {

        String refreshToken = request.getRefreshToken();

        if (refreshToken != null
                && jwtTokenProvider.validateToken(refreshToken)
                && jwtTokenProvider.isRefreshToken(refreshToken)) {

            String username = jwtTokenProvider.getUsername(refreshToken);
            refreshTokenStore.delete(username);
        }

        return ResponseEntity.noContent().build();
    }

    // ====== DTO들 ======

    @Data
    public static class LoginRequest {
        private String loginId;
        private String password;

//        public String getLoginId() {
//            return loginId;
//        }
//        public void setLoginId(String loginId) {
//            this.loginId = loginId;
//        }
//        public String getPassword() {
//            return password;
//        }
//        public void setPassword(String password) {
//            this.password = password;
//        }
    }

    @Data
    public static class TokenResponse {
        private String accessToken;
        private String refreshToken;

        public TokenResponse() {
        }

        public TokenResponse(String accessToken, String refreshToken) {
            this.accessToken = accessToken;
            this.refreshToken = refreshToken;
        }

//        public String getAccessToken() {
//            return accessToken;
//        }
//        public void setAccessToken(String accessToken) {
//            this.accessToken = accessToken;
//        }
//
//        public String getRefreshToken() {
//            return refreshToken;
//        }
//        public void setRefreshToken(String refreshToken) {
//            this.refreshToken = refreshToken;
//        }
    }

    @Data
    public static class RefreshRequest {
        private String refreshToken;

//        public String getRefreshToken() {
//            return refreshToken;
//        }
//        public void setRefreshToken(String refreshToken) {
//            this.refreshToken = refreshToken;
//        }
    }
}
