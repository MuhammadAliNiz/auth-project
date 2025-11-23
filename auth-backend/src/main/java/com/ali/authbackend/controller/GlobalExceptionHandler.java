package com.ali.authbackend.controller;

import com.ali.authbackend.dto.response.ApiResponse;
import com.ali.authbackend.dto.response.ErrorDetails;
import com.ali.authbackend.exception.EmailNotVerifiedException;
import com.ali.authbackend.exception.InvalidRefreshTokenException;
import com.ali.authbackend.exception.RefreshTokenNotFoundException;
import com.ali.authbackend.exception.ResourceAlreadyExistsException;
import com.ali.authbackend.exception.UserNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(RefreshTokenNotFoundException.class)
    public ResponseEntity<ApiResponse<Object>> handleRefreshTokenNotFound(
            RefreshTokenNotFoundException ex, HttpServletRequest request) {

        log.warn("Refresh token not found - Path: {}, Message: {}", request.getRequestURI(), ex.getMessage());

        ErrorDetails errorDetails = ErrorDetails.builder()
                .code("REFRESH_TOKEN_NOT_FOUND")
                .message(ex.getMessage())
                .details("Please login again to get a new refresh token")
                .build();

        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(ApiResponse.error(ex.getMessage(), HttpStatus.UNAUTHORIZED, errorDetails));
    }

    @ExceptionHandler(InvalidRefreshTokenException.class)
    public ResponseEntity<ApiResponse<Object>> handleInvalidRefreshToken(
            InvalidRefreshTokenException ex, HttpServletRequest request) {

        log.warn("Invalid refresh token - Path: {}, Message: {}", request.getRequestURI(), ex.getMessage());

        ErrorDetails errorDetails = ErrorDetails.builder()
                .code("INVALID_REFRESH_TOKEN")
                .message(ex.getMessage())
                .details("Your session has expired. Please login again")
                .build();

        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(ApiResponse.error(ex.getMessage(), HttpStatus.UNAUTHORIZED, errorDetails));
    }

    @ExceptionHandler(EmailNotVerifiedException.class)
    public ResponseEntity<ApiResponse<Object>> handleEmailNotVerified(
            EmailNotVerifiedException ex, HttpServletRequest request) {

        log.warn("Email not verified - Path: {}, Message: {}", request.getRequestURI(), ex.getMessage());

        ErrorDetails errorDetails = ErrorDetails.builder()
                .code("EMAIL_NOT_VERIFIED")
                .message(ex.getMessage())
                .details("Please verify your email address before accessing this resource")
                .build();

        Map<String, Object> data = new HashMap<>();
        data.put("verified", false);
        data.put("redirectTo", "/verify-email");

        ApiResponse<Object> response = ApiResponse.builder()
                .status(HttpStatus.FORBIDDEN.value())
                .success(false)
                .message(ex.getMessage())
                .data(data)
                .error(errorDetails)
                .timestamp(Instant.now())
                .build();

        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
    }

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<ApiResponse<Object>> handleUserNotFound(
            UserNotFoundException ex, HttpServletRequest request) {

        log.warn("User not found - Path: {}, Message: {}", request.getRequestURI(), ex.getMessage());

        ErrorDetails errorDetails = ErrorDetails.builder()
                .code("USER_NOT_FOUND")
                .message(ex.getMessage())
                .details("The requested user does not exist")
                .build();

        return ResponseEntity
                .status(HttpStatus.NOT_FOUND)
                .body(ApiResponse.error(ex.getMessage(), HttpStatus.NOT_FOUND, errorDetails));
    }

    @ExceptionHandler(ResourceAlreadyExistsException.class)
    public ResponseEntity<ApiResponse<Object>> handleResourceAlreadyExists(
            ResourceAlreadyExistsException ex, HttpServletRequest request) {

        log.warn("Resource already exists - Path: {}, Message: {}", request.getRequestURI(), ex.getMessage());

        ErrorDetails errorDetails = ErrorDetails.builder()
                .code("RESOURCE_ALREADY_EXISTS")
                .message(ex.getMessage())
                .details("The resource you're trying to create already exists")
                .build();

        return ResponseEntity
                .status(HttpStatus.CONFLICT)
                .body(ApiResponse.error(ex.getMessage(), HttpStatus.CONFLICT, errorDetails));
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiResponse<Object>> handleBadCredentials(
            BadCredentialsException ex, HttpServletRequest request) {

        log.warn("Bad credentials - Path: {}, Message: {}", request.getRequestURI(), ex.getMessage());

        ErrorDetails errorDetails = ErrorDetails.builder()
                .code("BAD_CREDENTIALS")
                .message("Invalid email or password")
                .details("Please check your credentials and try again")
                .build();

        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(ApiResponse.error("Invalid email or password", HttpStatus.UNAUTHORIZED, errorDetails));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse<Object>> handleValidationException(
            MethodArgumentNotValidException ex, HttpServletRequest request) {

        log.warn("Validation failed - Path: {}", request.getRequestURI());

        Map<String, String> fieldErrors = ex.getBindingResult().getFieldErrors().stream()
                .collect(Collectors.toMap(
                        FieldError::getField,
                        error -> error.getDefaultMessage() != null ? error.getDefaultMessage() : "Invalid value",
                        (existing, replacement) -> existing
                ));

        ErrorDetails errorDetails = ErrorDetails.builder()
                .code("VALIDATION_FAILED")
                .message("Validation failed")
                .details(fieldErrors.toString())
                .build();

        ApiResponse<Object> response = ApiResponse.builder()
                .status(HttpStatus.BAD_REQUEST.value())
                .success(false)
                .message("Validation failed")
                .data(Map.of("errors", fieldErrors))
                .error(errorDetails)
                .timestamp(Instant.now())
                .build();

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }
}