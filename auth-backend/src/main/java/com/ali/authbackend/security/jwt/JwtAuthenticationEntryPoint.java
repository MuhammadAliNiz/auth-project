package com.ali.authbackend.security.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException authException
    ) throws IOException {

        log.error("Unauthorized access attempt to: {} - {}",
                request.getRequestURI(),
                authException.getMessage());

        // Set response status and content type
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        // Build error response
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("status", HttpServletResponse.SC_UNAUTHORIZED);
        errorResponse.put("error", "Unauthorized");
        errorResponse.put("message", "Authentication required. Please provide a valid access token.");
        errorResponse.put("path", request.getRequestURI());
        errorResponse.put("timestamp", Instant.now().toString());

        // Check if it's a specific error type
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            errorResponse.put("details", "Missing or invalid Authorization header. Expected format: 'Bearer <token>'");
        } else {
            errorResponse.put("details", "Invalid or expired access token. Please refresh your token or login again.");
        }

        // Write JSON response
        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
    }
}