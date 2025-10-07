package com.sprintboot.webapp.plantilla.modules.users.api.controllers;

import com.sprintboot.webapp.plantilla.api.dto.ApiResponse;
import com.sprintboot.webapp.plantilla.modules.users.api.dto.*;
import com.sprintboot.webapp.plantilla.modules.users.application.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.*;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.util.UUID;

@Slf4j
@Tag(name = "Users")
@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService service;

    @Operation(summary = "Listar usuarios (USER/ADMIN)")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    @GetMapping
    public ResponseEntity<ApiResponse<Page<UserDTO>>> list(
            @RequestParam(required = false) String q,
            Pageable pageable) {
        log.info("GET /api/users q={} page={} size={}", q, pageable.getPageNumber(), pageable.getPageSize());
        Page<UserDTO> users = service.findAll(q, pageable);
        return ResponseEntity.ok(ApiResponse.of(users));
    }

    @Operation(summary = "Obtener usuario por ID (USER/ADMIN)")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<UserDTO>> get(@PathVariable UUID id) {
        log.info("GET /api/users/{}", id);
        UserDTO user = service.findById(id);
        return ResponseEntity.ok(ApiResponse.of(user));
    }

    @Operation(summary = "Crear usuario (ADMIN)")
    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping
    public ResponseEntity<ApiResponse<UserDTO>> create(@Valid @RequestBody CreateUserRequest req) {
        log.info("POST /api/users email={}", req.email());
        UserDTO created = service.create(req);
        return ResponseEntity
                .created(URI.create("/api/users/" + created.id()))
                .body(ApiResponse.success("Usuario creado exitosamente", created));
    }

    @Operation(summary = "Actualizar usuario (ADMIN)")
    @PreAuthorize("hasRole('ADMIN')")
    @PutMapping("/{id}")
    public ResponseEntity<ApiResponse<UserDTO>> update(
            @PathVariable UUID id,
            @Valid @RequestBody UpdateUserRequest req) {
        log.info("PUT /api/users/{} email={}", id, req.email());
        UserDTO updated = service.update(id, req);
        return ResponseEntity.ok(ApiResponse.success("Usuario actualizado exitosamente", updated));
    }

    @Operation(summary = "Eliminar usuario (ADMIN)")
    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/{id}")
    public ResponseEntity<ApiResponse<Void>> delete(@PathVariable UUID id) {
        log.info("DELETE /api/users/{}", id);
        service.delete(id);
        return ResponseEntity.ok(ApiResponse.message("Usuario eliminado exitosamente"));
    }
}