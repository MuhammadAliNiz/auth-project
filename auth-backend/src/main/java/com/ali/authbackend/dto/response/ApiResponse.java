package com.ali.authbackend.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApiResponse<T> {

    private int status;
    private boolean success;
    private String message;
    private T data;
    private ErrorDetails error;
    private Map<String, Object> metadata;
    @Builder.Default
    private Instant timestamp = Instant.now();

    public static <T> ApiResponse<T> success(T data) {
        return ApiResponse.<T>builder()
                .status(HttpStatus.OK.value())
                .success(true)
                .message("Request successful")
                .data(data)
                .timestamp(Instant.now())
                .build();
    }

    public static <T> ApiResponse<T> success(T data, String message) {
        return ApiResponse.<T>builder()
                .status(HttpStatus.OK.value())
                .success(true)
                .message(message)
                .data(data)
                .timestamp(Instant.now())
                .build();
    }

    public static <T> ApiResponse<T> success(T data, String message, HttpStatus status) {
        return ApiResponse.<T>builder()
                .status(status.value())
                .success(true)
                .message(message)
                .data(data)
                .timestamp(Instant.now())
                .build();
    }

    public static <T> ApiResponse<T> success(String message) {
        return ApiResponse.<T>builder()
                .status(HttpStatus.OK.value())
                .success(true)
                .message(message)
                .timestamp(Instant.now())
                .build();
    }

    public static <T> ApiResponse<T> created(T data, String message) {
        return ApiResponse.<T>builder()
                .status(HttpStatus.CREATED.value())
                .success(true)
                .message(message)
                .data(data)
                .timestamp(Instant.now())
                .build();
    }

    public static <T> ApiResponse<T> accepted(String message) {
        return ApiResponse.<T>builder()
                .status(HttpStatus.ACCEPTED.value())
                .success(true)
                .message(message)
                .timestamp(Instant.now())
                .build();
    }

    public static <T> ApiResponse<T> noContent() {
        return ApiResponse.<T>builder()
                .status(HttpStatus.NO_CONTENT.value())
                .success(true)
                .message("No content")
                .timestamp(Instant.now())
                .build();
    }

    public static <T> ApiResponse<T> error(String message, HttpStatus status) {
        return ApiResponse.<T>builder()
                .status(status.value())
                .success(false)
                .message(message)
                .error(ErrorDetails.builder()
                        .code(status.name())
                        .message(message)
                        .build())
                .timestamp(Instant.now())
                .build();
    }

    public static <T> ApiResponse<T> error(T data, String message) {
        return ApiResponse.<T>builder()
                .status(HttpStatus.BAD_REQUEST.value())
                .success(false)
                .message(message)
                .data(data)
                .timestamp(Instant.now())
                .build();
    }

    public static <T> ApiResponse<T> error(String message, HttpStatus status, ErrorDetails errorDetails) {
        return ApiResponse.<T>builder()
                .status(status.value())
                .success(false)
                .message(message)
                .error(errorDetails)
                .timestamp(Instant.now())
                .build();
    }


}