package com.ali.authbackend.repository;

import com.ali.authbackend.entity.ForgetPassword;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.Optional;

public interface ForgetPasswordRepository extends JpaRepository<ForgetPassword, String> {
    // Single current token (unique user_id)
    Optional<ForgetPassword> findByUserEmail(String email);

    // Active (unused & not expired) token
    Optional<ForgetPassword> findByUserEmailAndUsedFalseAndExpirationDateAfter(String email, Instant now);

    // If multiple tokens allowed, newest valid
    Optional<ForgetPassword> findTopByUserEmailAndUsedFalseAndExpirationDateAfterOrderByCreatedAtDesc(String email, Instant now);
}