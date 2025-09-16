package com.sprintboot.webapp.plantilla.modules.auth.api.dto;


import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record AuthLoginRequest(@NotBlank @Email String email, @NotBlank String password) {
}