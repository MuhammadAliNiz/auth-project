package com.ali.authbackend.security.filter;

import com.ali.authbackend.dto.response.ApiResponse;
import com.ali.authbackend.entity.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Set;

@Component
@RequiredArgsConstructor
public class EmailVerificationFilter extends OncePerRequestFilter {

    private static final Set<String> ALLOWED_UNVERIFIED_ENDPOINTS = Set.of(
            "/api/auth/login",
            "/api/auth/verify-email",
            "/api/auth/resend-verification-email"
    );

    private final ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        String path = request.getRequestURI();

        if (ALLOWED_UNVERIFIED_ENDPOINTS.contains(path)) {
            filterChain.doFilter(request, response);
            return;
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null
                || !authentication.isAuthenticated()
                || authentication instanceof AnonymousAuthenticationToken) {

            filterChain.doFilter(request, response);

            return;
        }

        Object principal = authentication.getPrincipal();

        if (principal instanceof User userDetails && !userDetails.isEmailVerified()) {

            response.setStatus(HttpStatus.FORBIDDEN.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            ApiResponse<Void> body = ApiResponse.error(null, "Email is not verified");
            response.getWriter().write(objectMapper.writeValueAsString(body));

            return;
        }

        filterChain.doFilter(request, response);
    }
}