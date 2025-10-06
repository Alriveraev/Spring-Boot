package com.sprintboot.webapp.plantilla.modules.users.application;

import com.sprintboot.webapp.plantilla.exceptions.NotFoundException;
import com.sprintboot.webapp.plantilla.modules.users.api.dto.*;
import com.sprintboot.webapp.plantilla.modules.users.domain.Role;
import com.sprintboot.webapp.plantilla.modules.users.domain.User;
import com.sprintboot.webapp.plantilla.modules.users.infrastructure.mapper.UserMapper;
import com.sprintboot.webapp.plantilla.modules.users.infrastructure.repository.RoleRepository;
import com.sprintboot.webapp.plantilla.modules.users.infrastructure.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.*;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository users;
    private final RoleRepository roles;
    private final UserMapper mapper;
    private final PasswordEncoder encoder;

    @Transactional(readOnly = true)
    public Page<UserDTO> findAll(String q, Pageable pageable) {
        log.debug("UserService.findAll q='{}' page={}", q, pageable);

        if (q == null || q.isBlank()) {
            return users.findAll(pageable).map(mapper::toDTO);
        }

        String like = "%" + q.toLowerCase() + "%";
        Specification<User> spec = (root, cq, cb) -> cb.or(
                cb.like(cb.lower(root.get("firstName")), like),
                cb.like(cb.lower(root.get("lastName")), like),
                cb.like(cb.lower(root.get("email")), like)
        );

        return users.findAll(spec, pageable).map(mapper::toDTO);
    }

    @Transactional(readOnly = true)
    public UserDTO findById(Long id) {
        log.debug("UserService.findById id={}", id);
        User user = users.findById(id)
                .orElseThrow(() -> new NotFoundException("Usuario no encontrado con ID: " + id));
        return mapper.toDTO(user);
    }

    @Transactional
    public UserDTO create(CreateUserRequest req) {
        log.info("UserService.create email={}", req.email());

        String email = req.email().trim().toLowerCase();

        if (users.existsByEmailNormalized(email)) {
            throw new DataIntegrityViolationException("El email ya está en uso");
        }

        Set<Role> assignedRoles = fetchRoles(req.roles());

        User user = User.builder()
                .firstName(req.firstName())
                .lastName(req.lastName())
                .email(email)
                .passwordHash(encoder.encode(req.password()))
                .roles(assignedRoles)
                .build();

        User saved = users.save(user);
        log.info("Usuario creado exitosamente: id={} email={}", saved.getId(), saved.getEmail());

        return mapper.toDTO(saved);
    }

    @Transactional
    public UserDTO update(Long id, UpdateUserRequest req) {
        log.debug("UserService.update id={} email={}", id, req.email());

        User user = users.findById(id)
                .orElseThrow(() -> new NotFoundException("Usuario no encontrado con ID: " + id));

        String email = req.email().trim().toLowerCase();

        if (!email.equals(user.getEmail()) && users.existsByEmailNormalized(email)) {
            throw new DataIntegrityViolationException("El email ya está en uso");
        }

        user.setFirstName(req.firstName());
        user.setLastName(req.lastName());
        user.setEmail(email);
        user.setRoles(fetchRoles(req.roles()));

        User updated = users.save(user);
        log.info("Usuario actualizado exitosamente: id={}", id);

        return mapper.toDTO(updated);
    }

    @Transactional
    public void delete(Long id) {
        log.debug("UserService.delete id={}", id);

        if (!users.existsById(id)) {
            throw new NotFoundException("Usuario no encontrado con ID: " + id);
        }

        users.deleteById(id);
        log.info("Usuario eliminado exitosamente: id={}", id);
    }

    private Set<Role> fetchRoles(Set<String> codes) {
        return codes.stream()
                .map(code -> roles.findByCode(code)
                        .orElseThrow(() -> new NotFoundException("Rol no encontrado: " + code)))
                .collect(Collectors.toSet());
    }
}