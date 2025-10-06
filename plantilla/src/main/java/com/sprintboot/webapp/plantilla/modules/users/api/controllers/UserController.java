package com.sprintboot.webapp.plantilla.modules.users.api.controllers;


import com.sprintboot.webapp.plantilla.modules.users.api.dto.*;
import com.sprintboot.webapp.plantilla.modules.users.application.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.*;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.net.URI;

@Slf4j
@Tag(name = "Users")
@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
@Validated
public class UserController {

    private final UserService service;

    @Operation(summary = "Listar usuarios (USER/ADMIN)")
    @GetMapping
    public ResponseEntity<Page<UserDTO>> list(@RequestParam(required = false) String q, Pageable pageable) {
        log.info("GET /api/users q={} page={} size={} sort={}", q, pageable.getPageNumber(), pageable.getPageSize(), pageable.getSort());
        return ResponseEntity.ok(service.findAll(q, pageable));
    }

    @Operation(summary = "Obtener usuario por ID (USER/ADMIN)")
    @GetMapping("/{id}")
    public ResponseEntity<UserDTO> get(@PathVariable Long id) {
        log.info("GET /api/users/{}", id);
        return ResponseEntity.ok(service.findById(id));
    }

    @Operation(summary = "Crear usuario (ADMIN)")
    @PostMapping
    public ResponseEntity<UserDTO> create(@RequestBody @Valid CreateUserRequest req) {
        log.info("POST /api/users email={}", req.email());
        UserDTO created = service.create(req);
        return ResponseEntity.created(URI.create("/api/users/" + created.id())).body(created);
    }

    @Operation(summary = "Actualizar usuario (ADMIN)")
    @PutMapping("/{id}")
    public ResponseEntity<UserDTO> update(@PathVariable Long id, @Valid @RequestBody UpdateUserRequest req) {
        log.info("PUT /api/users/{} email={}", id, req.email());
        return ResponseEntity.ok(service.update(id, req));
    }

    @Operation(summary = "Eliminar usuario (ADMIN)")
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        log.info("DELETE /api/users/{}", id);
        service.delete(id);
        return ResponseEntity.noContent().build();
    }
}
