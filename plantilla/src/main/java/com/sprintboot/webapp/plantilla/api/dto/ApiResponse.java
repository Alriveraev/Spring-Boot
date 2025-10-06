package com.sprintboot.webapp.plantilla.api.dto;

import java.time.Instant;

public record ApiResponse<T>(
        String message,  // ← Ahora es opcional (puede ser null)
        T data,
        Instant timestamp
) {
    // Con mensaje
    public static <T> ApiResponse<T> success(String message, T data) {
        return new ApiResponse<>(message, data, Instant.now());
    }

    public static <T> ApiResponse<T> of(T data) {
        return new ApiResponse<>(null, data, Instant.now());
    }
}