package com.ali.authbackend.controller;

import ch.qos.logback.core.model.Model;
import com.ali.authbackend.annotation.RateLimit;
import com.ali.authbackend.dto.request.*;
import com.ali.authbackend.dto.response.ApiResponse;
import com.ali.authbackend.dto.response.EmailAvailabilityCheckResponse;
import com.ali.authbackend.dto.response.EmailVerificationResponse;
import com.ali.authbackend.dto.response.AuthResponse;
import com.ali.authbackend.service.AuthenticationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    @RateLimit
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<AuthResponse>> login(
            @Validated @RequestBody LoginRequest loginRequest,
            HttpServletRequest httpServletRequest,
            HttpServletResponse httpServletResponse
    ) {

        AuthResponse response = authenticationService.login(
                loginRequest,
                httpServletRequest,
                httpServletResponse
        );

        ApiResponse<AuthResponse> apiResponse =
                ApiResponse.success(response, "User logged in successfully");

        return ResponseEntity
                .status(HttpStatus.OK)
                .body(apiResponse);
    }

    @RateLimit(capacity = 5, refillTokens = 5, refillMinutes = 1)
    @PostMapping("/email-availability")
    public ResponseEntity<ApiResponse<EmailAvailabilityCheckResponse>> isEmailAvailable(
            @Validated @RequestBody EmailAvailabilityRequest request) {

        boolean available = authenticationService.checkEmailAvailability(request.getEmail());

        EmailAvailabilityCheckResponse response = new EmailAvailabilityCheckResponse(available);
        String message = available ? "Email is available" : "Email is not available";

        return ResponseEntity.ok(ApiResponse.success(response, message));
    }


    @RateLimit(capacity = 3, refillTokens = 3, refillMinutes = 5)
    @PostMapping("/register")
    public ResponseEntity<ApiResponse<AuthResponse>> register(
            @Validated @RequestBody RegisterRequest registerRequest,
            HttpServletResponse httpServletResponse,
            HttpServletRequest httpServletRequest){

        AuthResponse response = authenticationService.register(
                registerRequest,
                httpServletRequest,
                httpServletResponse);

        ApiResponse<AuthResponse> apiResponse =
                ApiResponse.created(response,"User registered successfully");

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(apiResponse);
    }


    @RateLimit(capacity = 3, refillTokens = 3, refillMinutes = 1)
    @PostMapping("/verify-email")
    public ResponseEntity<ApiResponse<EmailVerificationResponse>> verifyEmail(
            @Validated @RequestBody EmailVerificationRequest request) {

        boolean verified = authenticationService.verifyEmail(request);

        if (verified) {
            return ResponseEntity.ok(
                    ApiResponse.success(
                            new EmailVerificationResponse(true),
                            "Email verified successfully"
                    )
            );
        }

        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(ApiResponse.error(
                        new EmailVerificationResponse(false),
                        "Invalid or expired verification code"
                ));
    }

    @RateLimit(capacity = 5, refillTokens = 5, refillMinutes = 1)
    @PostMapping("/resend-verification-email")
    public ResponseEntity<ApiResponse<Map<String, String>>> resendVerificationEmail() {

        authenticationService.resendVerificationEmail();

            return ResponseEntity.ok(
                    ApiResponse.success(
                            Map.of("message", "Verification email sent successfully"),
                            "Verification email sent successfully"
                    )
            );

    }


    @RateLimit(capacity = 3, refillTokens = 3, refillMinutes = 5)
    @PostMapping("/forgot-password")
    public ResponseEntity<ApiResponse<Map<String, Boolean>>> forgotPassword(
            @Validated @RequestBody ForgetPasswordRequest request) {

        try {
            authenticationService.sendForgotPasswordEmail(request.getEmail());
            return ResponseEntity.ok(
                    ApiResponse.success(
                            Map.of("sent", true),
                            "If your email exists, you will receive a password reset link"
                    )
            );
        } catch (Exception e) {
            log.error("Error in forgot password process for email: {}", request.getEmail(), e.getCause());

            return ResponseEntity.ok(
                    ApiResponse.success(
                            Map.of("sent", true),
                            "If your email exists, you will receive a password reset link"
                    )
            );
        }
    }


    @RateLimit(capacity = 5, refillTokens = 5, refillMinutes = 1)
    @GetMapping("/validate-reset-token")
    public ResponseEntity<ApiResponse<Map<String, Boolean>>> validateResetToken(
            @RequestParam String token) {

        boolean valid = authenticationService.validateResetToken(token);

        return ResponseEntity.ok(
                ApiResponse.success(
                        Map.of("valid", valid),
                        valid ? "Token is valid" : "Token is invalid or expired"
                )
        );
    }


    @RateLimit(capacity = 3, refillTokens = 3, refillMinutes = 5)
    @PostMapping("/reset-password")
    public ResponseEntity<ApiResponse<Map<String, Boolean>>> resetPassword(
            @Validated @RequestBody ResetPasswordRequest request) {

        try {
            authenticationService.resetPassword(request);
            return ResponseEntity.ok(
                    ApiResponse.success(
                            Map.of("reset", true),
                            "Password reset successfully"
                    )
            );
        } catch (RuntimeException e) {
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponse.error(
                            Map.of("reset", false),
                            e.getMessage()
                    ));
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Map<String, Boolean>>> logout(){
        authenticationService.logout();

        ApiResponse<Map<String, Boolean>> apiResponse =
                ApiResponse.success(
                        Map.of("loggedOut", true),
                        "User logged out successfully"
                );

        return ResponseEntity
                .status(HttpStatus.OK)
                .body(apiResponse);
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<ApiResponse<AuthResponse>> refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ){
        AuthResponse response12 = authenticationService.refreshToken(request, response);

        ApiResponse<AuthResponse> apiResponse =
                ApiResponse.success(response12, "Token refreshed successfully");

        return ResponseEntity
                .status(HttpStatus.OK)
                .body(apiResponse);
    }


}
