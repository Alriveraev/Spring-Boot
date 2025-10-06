package com.sprintboot.webapp.plantilla.modules.auth.api.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record AuthLoginRequest(
        @NotBlank(message = "La email es obligatoria")
        @Email(message = "Debe ser un email válido")
        @Size(min = 4, max = 255, message = "El email debe tener entre 4 y 255 caracteres")
        String email,

        @NotBlank(message = "La contraseña es obligatoria")
        @Size(min = 6, message = "La contraseña debe tener al menos 6 caracteres")
        String password
) {}