// com.example.jwt_sample.config.jwt.RefreshTokenStore

package com.example.jwt_sample.config.jwt;

import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class RefreshTokenStore {

    // username -> refreshToken
    private final Map<String, String> store = new ConcurrentHashMap<>();

    public void save(String username, String refreshToken) {
        store.put(username, refreshToken);
    }

    public boolean isValid(String username, String refreshToken) {
        return refreshToken != null && refreshToken.equals(store.get(username));
    }

    public void delete(String username) {
        store.remove(username);
    }
}
