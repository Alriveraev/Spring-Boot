package com.sprintboot.webapp.plantilla.api.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.Instant;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record ApiResponse<T>(
        String message,
        T data,
        Instant timestamp
) {
    // Con mensaje y data
    public static <T> ApiResponse<T> success(String message, T data) {
        return new ApiResponse<>(message, data, Instant.now());
    }

    // Solo data (sin mensaje)
    public static <T> ApiResponse<T> of(T data) {
        return new ApiResponse<>(null, data, Instant.now());
    }

    // Solo mensaje (sin data)
    public static <T> ApiResponse<T> message(String message) {
        return new ApiResponse<>(message, null, Instant.now());
    }
}