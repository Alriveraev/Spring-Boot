package com.sprintboot.webapp.plantilla.modules.users.api.dto;

import java.util.Set;
import java.util.UUID;

public record UserDTO(
        UUID id,
        String firstName,
        String lastName,
        String email,
        Set<String> roles
) {}