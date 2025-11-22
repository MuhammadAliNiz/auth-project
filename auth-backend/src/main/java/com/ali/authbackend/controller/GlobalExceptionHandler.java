package com.ali.authbackend.controller;


import com.ali.authbackend.dto.response.ApiResponse;
import com.ali.authbackend.exception.EmailNotVerifiedException;
import com.ali.authbackend.exception.ResourceAlreadyExistsException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@RequiredArgsConstructor
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidationException(MethodArgumentNotValidException ex) {
        Map<String, String> fieldErrors = new HashMap<>();

        ex.getBindingResult().getFieldErrors().forEach(error ->
                fieldErrors.put(error.getField(), error.getDefaultMessage())
        );

        Map<String, Object> response = new HashMap<>();
        response.put("success", false);
        response.put("message", "Validation failed");
        response.put("errors", fieldErrors);
        response.put("timestamp", LocalDateTime.now());

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }


    @ExceptionHandler(ResourceAlreadyExistsException.class)
    public ResponseEntity<ApiResponse<Object>> resourceAlreadyExistsException(
            ResourceAlreadyExistsException ex) {

        ApiResponse<Object> errorResponse = ApiResponse.error(
                ex.getMessage(),
                HttpStatus.CONFLICT
        );

        return new ResponseEntity<>(errorResponse, HttpStatus.CONFLICT);
    }

    @ExceptionHandler(EmailNotVerifiedException.class)
    public ResponseEntity<ApiResponse<Map<String, Object>>> handleEmailNotVerified(
            EmailNotVerifiedException ex) {

        log.warn("Email not verified exception: {}", ex.getMessage());

        Map<String, Object> data = new HashMap<>();
        data.put("verified", false);
        data.put("redirectTo", "/verify-email");

        return ResponseEntity
                .status(HttpStatus.FORBIDDEN)
                .body(ApiResponse.<Map<String, Object>>builder()
                        .status(HttpStatus.FORBIDDEN.value())
                        .success(false)
                        .message(ex.getMessage())
                        .data(data)
                        .timestamp(java.time.Instant.now())
                        .build());
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiResponse<Map<String, Object>>> handleBadCredentials(
            BadCredentialsException ex) {

        log.warn("Bad credentials exception: {}", ex.getMessage());

        Map<String, Object> data = new HashMap<>();
        data.put("authenticated", false);

        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(ApiResponse.<Map<String, Object>>builder()
                        .status(HttpStatus.UNAUTHORIZED.value())
                        .success(false)
                        .message(ex.getMessage())
                        .data(data)
                        .timestamp(java.time.Instant.now())
                        .build());
    }

}
