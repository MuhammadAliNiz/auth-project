package com.ali.authbackend.util;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
@RequiredArgsConstructor
public class CookieUtils {

    public ResponseCookie createHttpOnlyCookie(String name, String value, long maxAgeSeconds) {
        return ResponseCookie.from(name, value)
                .httpOnly(true)
                .secure(false) // Should be true in production
                .sameSite("Strict")
                .path("/")
                .maxAge(maxAgeSeconds)
                .build();
    }

    public Optional<String> extractCookieValue(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(name)) {
                    return cookie.getValue().describeConstable();
                }
            }
        }
        return  Optional.empty();
    }

    public ResponseCookie deleteHttpOnlyCookie(String name) {
        return ResponseCookie.from(name, "")
                .httpOnly(true)
                .secure(true) // Must match the properties of the cookie being deleted
                .sameSite("Strict")
                .path("/")
                .maxAge(0) // The key to deleting the cookie
                .build();
    }
}
