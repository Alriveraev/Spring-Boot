package com.sprintboot.webapp.plantilla.modules.users.api.dto;

import java.util.Set;
import java.util.UUID;

public record UserDTO(
        UUID id,  // ✅ Cambiado de Long a UUID
        String firstName,
        String lastName,
        String email,
        Set<String> roles
) {}