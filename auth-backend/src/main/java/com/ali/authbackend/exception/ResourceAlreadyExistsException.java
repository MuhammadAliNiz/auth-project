package com.ali.authbackend.exception;

import lombok.Getter;

@Getter
public class ResourceAlreadyExistsException extends RuntimeException {
    public ResourceAlreadyExistsException(String message) {
        super(message);
    }
}

