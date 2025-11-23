package com.ali.authbackend.service;

import com.ali.authbackend.dto.request.EmailVerificationRequest;
import com.ali.authbackend.dto.request.LoginRequest;
import com.ali.authbackend.dto.request.RegisterRequest;
import com.ali.authbackend.dto.request.ResetPasswordRequest;
import com.ali.authbackend.dto.response.AuthResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public interface AuthenticationService {

    AuthResponse register(RegisterRequest registerRequest, HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse);

    boolean checkEmailAvailability(String email);

    boolean verifyEmail(EmailVerificationRequest emailVerificationRequest);

    void resendVerificationEmail();

    AuthResponse login(LoginRequest loginRequest, HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse);

    void sendForgotPasswordEmail(String email);

    boolean validateResetToken(String token);

    void resetPassword(ResetPasswordRequest request);

    AuthResponse refreshToken(HttpServletRequest request, HttpServletResponse response);

    void logout();
}
