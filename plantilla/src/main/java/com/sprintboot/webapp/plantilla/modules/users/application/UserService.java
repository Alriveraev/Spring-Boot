package com.sprintboot.webapp.plantilla.modules.users.application;

import com.sprintboot.webapp.plantilla.modules.users.api.dto.*;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.UUID;

public interface UserService {
    Page<UserDTO> findAll(String q, Pageable pageable);
    UserDTO findById(UUID id);
    UserDTO create(CreateUserRequest req);
    UserDTO update(UUID id, UpdateUserRequest req);
    void delete(UUID id);
}