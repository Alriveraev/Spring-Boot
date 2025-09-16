package com.sprintboot.webapp.plantilla.modules.users.application;

import com.sprintboot.webapp.plantilla.modules.users.api.dto.*;
import org.springframework.data.domain.*;

public interface UserService {
    Page<UserDTO> findAll(String q, Pageable pageable);

    UserDTO findById(Long id);

    UserDTO create(CreateUserRequest req);

    UserDTO update(Long id, UpdateUserRequest req);

    void delete(Long id);
}
