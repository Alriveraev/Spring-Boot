package com.sprintboot.webapp.plantilla.modules.auth.api.dto;

import jakarta.validation.constraints.NotBlank;

public record AuthLogoutRequest(@NotBlank String refreshToken) {
}
