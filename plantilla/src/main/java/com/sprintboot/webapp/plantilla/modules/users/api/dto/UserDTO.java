package com.sprintboot.webapp.plantilla.modules.users.api.dto;


import java.util.Set;

public record UserDTO(Long id, String firstName, String lastName, String email, Set<String> roles) {
}
