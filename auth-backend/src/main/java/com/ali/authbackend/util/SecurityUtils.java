package com.ali.authbackend.util;

import com.ali.authbackend.entity.User;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.UUID;

@Component
public class SecurityUtils {

    public Optional<User> getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if(authentication == null
                || !authentication.isAuthenticated()
                || "anonymousUser".equals(authentication.getPrincipal())) {
            return Optional.empty();
        }

        Object principal = authentication.getPrincipal();
        if (principal instanceof User) {
            return Optional.of((User) principal);
        }

        return Optional.empty();
    }

    public Optional<UUID> getCurrentUserId() {
        return getCurrentUser().map(User::getUserId);
    }

    public Optional<String> getCurrentUserEmail() {
        return getCurrentUser().map(User::getEmail);
    }
}
