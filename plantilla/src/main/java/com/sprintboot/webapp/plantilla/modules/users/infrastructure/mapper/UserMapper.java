package com.sprintboot.webapp.plantilla.modules.users.infrastructure.mapper;

import com.sprintboot.webapp.plantilla.modules.users.api.dto.UserDTO;
import com.sprintboot.webapp.plantilla.modules.users.domain.Role;
import com.sprintboot.webapp.plantilla.modules.users.domain.User;
import org.mapstruct.*;

import java.util.Set;
import java.util.stream.Collectors;

@Mapper(componentModel = "spring")
public interface UserMapper {
    @Mapping(target = "roles", expression = "java(toCodes(entity.getRoles()))")
    UserDTO toDTO(User entity);

    default Set<String> toCodes(Set<Role> roles) {
        return roles.stream().map(Role::getCode).collect(Collectors.toSet());
    }
}
