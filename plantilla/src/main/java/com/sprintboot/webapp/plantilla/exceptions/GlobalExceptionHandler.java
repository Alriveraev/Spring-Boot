package com.sprintboot.webapp.plantilla.exceptions;

import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.*;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.*;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    public record ApiError(Instant timestamp, int status, String error, String message, String path,
                           Map<String, String> fieldErrors) {
    }

    @ExceptionHandler(NotFoundException.class)
    public ResponseEntity<ApiError> notFound(NotFoundException ex, org.springframework.web.context.request.WebRequest req) {
        log.error("NotFoundException: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(new ApiError(Instant.now(), 404, "Not Found", ex.getMessage(), req.getDescription(false), null));
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ApiError> conflict(DataIntegrityViolationException ex, org.springframework.web.context.request.WebRequest req) {
        log.error("DataIntegrityViolationException: {}", ex.getMostSpecificCause().getMessage());
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(new ApiError(Instant.now(), 409, "Conflict", ex.getMostSpecificCause().getMessage(), req.getDescription(false), null));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiError> badRequest(MethodArgumentNotValidException ex, org.springframework.web.context.request.WebRequest req) {
        Map<String, String> fields = new LinkedHashMap<>();
        for (FieldError fe : ex.getBindingResult().getFieldErrors()) {
            fields.put(fe.getField(), fe.getDefaultMessage());
        }
        log.error("Validation failed: {}", fields);
        return ResponseEntity.badRequest()
                .body(new ApiError(Instant.now(), 400, "Bad Request", "Validation failed", req.getDescription(false), fields));
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiError> unauthorized(Exception ex, org.springframework.web.context.request.WebRequest req) {
        log.error("BadCredentialsException: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new ApiError(Instant.now(), 401, "Unauthorized", ex.getMessage(), req.getDescription(false), null));
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiError> forbidden(Exception ex, org.springframework.web.context.request.WebRequest req) {
        log.info("AccessDeniedException: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(new ApiError(Instant.now(), 403, "Forbidden", ex.getMessage(), req.getDescription(false), null));
    }

    // Captura cualquier otra excepción no manejada
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> handleGenericException(Exception ex, org.springframework.web.context.request.WebRequest req) {
        log.error("Unhandled exception: ", ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ApiError(Instant.now(), 500, "Internal Server Error", ex.getMessage(), req.getDescription(false), null));
    }
}