package com.ali.authbackend.repository;

import com.ali.authbackend.entity.ForgetPassword;
import com.ali.authbackend.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.Optional;

public interface ForgetPasswordRepository extends JpaRepository<ForgetPassword, String> {

    Optional<ForgetPassword> findByUserEmail(String email);

    Optional<ForgetPassword> findByResetToken(String resetToken);

    Optional<ForgetPassword> findByResetTokenAndUsedFalseAndExpirationDateAfter(String resetToken, Instant now);

    void deleteByUser_Email(String email);
}