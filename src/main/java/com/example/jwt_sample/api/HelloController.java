package com.example.jwt_sample.api;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/hello")
public class HelloController {

    @GetMapping
    public String hello(Authentication authentication) {
        String username = (authentication != null) ? authentication.getName() : "anonymous";
        return "Hello, " + username + "!";
    }

    // ✅ USER/ADMIN 공용
    @GetMapping("/user")
    public String helloUser(Authentication authentication) {
        String username = (authentication != null) ? authentication.getName() : "anonymous";
        return "[USER API] Hello, " + username;
    }

    // ✅ ADMIN만 허용 (SecurityConfig의 URL 규칙 + @PreAuthorize 둘 다 예제로 걸어봄)
    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String helloAdmin(Authentication authentication) {
        String username = (authentication != null) ? authentication.getName() : "anonymous";
        return "[ADMIN API] Hello, " + username;
    }
}
