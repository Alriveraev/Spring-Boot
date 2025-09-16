package com.sprintboot.webapp.plantilla.modules.users.api.dto;


import jakarta.validation.constraints.*;

import java.util.Set;

public record UpdateUserRequest(
        @NotBlank @Size(max = 60) String firstName,
        @NotBlank @Size(max = 60) String lastName,
        @NotBlank @Email @Size(max = 320) String email,
        @NotEmpty Set<@Pattern(regexp = "^[A-Z_]{2,64}$") String> roles
) {
}
