package com.example.jwt_sample.config;

import com.example.jwt_sample.config.jwt.JwtAuthenticationFilter;
import com.example.jwt_sample.config.jwt.JwtTokenProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true) // ✅ @PreAuthorize 사용하려고 추가
public class SecurityConfig {

    private final JwtTokenProvider jwtTokenProvider;

    public SecurityConfig(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    // 연습용 InMemory 유저 (loginId: user / pw: 1234)
    @Bean
    public UserDetailsService userDetailsService() {
        return new InMemoryUserDetailsManager(
                User.withUsername("user")
                        .password("{noop}1234")  // {noop} = 패스워드 인코딩 안 함
                        .roles("USER")
                        .build(),
                User.withUsername("admin")
                        .password("{noop}1234")
                        .roles("ADMIN")
                        .build()
        );
    }

    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/login").permitAll()
                        .requestMatchers("/api/auth/refresh").permitAll()   // ✅ 추가
                        .requestMatchers("/api/auth/logout").permitAll()    // 연습용으로 permitAll

                        // ✅ 권한에 따라 접근 제한
                        .requestMatchers("/api/hello/user").hasAnyRole("USER", "ADMIN")
                        .requestMatchers("/api/hello/admin").hasRole("ADMIN")

                        .anyRequest().authenticated()
                )
                .addFilterBefore(
                        new JwtAuthenticationFilter(jwtTokenProvider),
                        UsernamePasswordAuthenticationFilter.class
                );

        return http.build();
    }
}
