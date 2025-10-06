package com.sprintboot.webapp.plantilla.modules.users.api.dto;

import jakarta.validation.constraints.*;

import java.util.Set;

public record CreateUserRequest(
        @NotBlank(message = "El nombre no puede estar vacío")
        @Size(min = 3, max = 60, message = "El nombre debe tener entre 3 y 60 caracteres")
        String firstName,

        @NotBlank(message = "El apellido no puede estar vacío")
        @Size(max = 60, message = "El apellido no puede exceder 60 caracteres")
        String lastName,

        @NotBlank(message = "El email no puede estar vacío")
        @Email(message = "El formato del email es inválido")
        String email,

        @NotBlank(message = "La contraseña no puede estar vacía")
        @Size(min = 8, max = 100, message = "La contraseña debe tener entre 8 y 100 caracteres")
        String password,

        @NotEmpty(message = "Debe asignar al menos un rol")
        @Pattern(regexp = "^[A-Z_]{2,64}$", message = "Los roles deben estar en mayúsculas")
        Set<String> roles
) {
}