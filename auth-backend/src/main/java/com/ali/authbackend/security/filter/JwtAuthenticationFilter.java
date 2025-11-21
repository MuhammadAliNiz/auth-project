package com.ali.authbackend.security.filter;

import com.ali.authbackend.security.jwt.JwtTokenProvider;
import com.ali.authbackend.service.impl.UserDetailsServiceImpl;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtTokenProvider jwtTokenProvider;
    private final UserDetailsServiceImpl userDetailsService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        try {
            final String jwt = jwtTokenProvider.extractJwtFromRequest(request);

            if (!StringUtils.hasText(jwt)) {
                log.debug("No JWT token found in request to: {}", request.getRequestURI());
                filterChain.doFilter(request, response);
                return;
            }

            if (!jwtTokenProvider.validateToken(jwt)) {
                log.warn("Invalid JWT token in request to: {}", request.getRequestURI());
                filterChain.doFilter(request, response);
                return;
            }

            Claims claims = jwtTokenProvider.parseToken(jwt);

            String tokenType = claims.get("type", String.class);

            if (!"access".equals(tokenType)) {
                log.warn("Invalid token type '{}' used for authentication. Expected 'access' token", tokenType);
                filterChain.doFilter(request, response);
                return;
            }

            String email = jwtTokenProvider.getEmailFromToken(jwt);

            if (email == null) {
                log.warn("No email found in JWT token");
                filterChain.doFilter(request, response);
                return;
            }

            if (SecurityContextHolder.getContext().getAuthentication() != null) {
                log.debug("User already authenticated: {}", email);
                filterChain.doFilter(request, response);
                return;
            }

            UserDetails userDetails = userDetailsService.loadUserByUsername(email);

            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );

            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(authentication);


            log.debug("Successfully authenticated user: {} for path: {}",
                    email, request.getRequestURI());

        }catch (Exception ex){
            log.error("Could not set user authentication in security context", ex);
        }
        filterChain.doFilter(request, response);
    }
}
