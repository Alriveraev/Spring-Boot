package com.sprintboot.webapp.plantilla.modules.users.application;

import com.sprintboot.webapp.plantilla.exceptions.NotFoundException;
import com.sprintboot.webapp.plantilla.modules.users.api.dto.*;
import com.sprintboot.webapp.plantilla.modules.users.domain.Role;
import com.sprintboot.webapp.plantilla.modules.users.domain.User;
import com.sprintboot.webapp.plantilla.modules.users.infrastructure.mapper.UserMapper;
import com.sprintboot.webapp.plantilla.modules.users.infrastructure.repository.RoleRepository;
import com.sprintboot.webapp.plantilla.modules.users.infrastructure.repository.UserRepository;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.*;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.annotation.Validated;

import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
@Validated  // ← AGREGA ESTO
@Transactional
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository users;
    private final RoleRepository roles;
    private final UserMapper mapper;
    private final PasswordEncoder encoder;

    @Transactional(readOnly = true)
    @PreAuthorize("hasAnyRole('USER','ADMIN')")
    public Page<UserDTO> findAll(String q, Pageable pageable) {
        log.debug("UserService.findAll q='{}' page={}", q, pageable);
        if (q == null || q.isBlank()) return users.findAll(pageable).map(mapper::toDTO);
        String like = "%" + q.toLowerCase() + "%";
        Specification<User> spec = (root, cq, cb) -> cb.or(
                cb.like(cb.lower(root.get("firstName")), like),
                cb.like(cb.lower(root.get("lastName")), like),
                cb.like(cb.lower(root.get("email")), like)
        );
        return users.findAll(spec, pageable).map(mapper::toDTO);
    }

    @Transactional(readOnly = true)
    @PreAuthorize("hasAnyRole('USER','ADMIN')")
    public UserDTO findById(Long id) {
        log.debug("UserService.findById id={}", id);
        User u = users.findById(id).orElseThrow(() -> new NotFoundException("User not found"));
        return mapper.toDTO(u);
    }

    @PreAuthorize("hasRole('ADMIN')")
    public UserDTO create(@Valid CreateUserRequest req) {  // ← AGREGA @Valid AQUÍ
        log.info("UserService.create email={}", req.email());
        String email = req.email().trim().toLowerCase();
        if (users.existsByEmailNormalized(email)) throw new DataIntegrityViolationException("Email already in use");

        Set<Role> assigned = fetchRoles(req.roles());
        User u = User.builder()
                .firstName(req.firstName()).lastName(req.lastName())
                .email(email).passwordHash(encoder.encode(req.password()))
                .roles(assigned).build();
        return mapper.toDTO(users.save(u));
    }

    @PreAuthorize("hasRole('ADMIN')")
    public UserDTO update(Long id, @Valid UpdateUserRequest req) {  // ← AGREGA @Valid AQUÍ
        log.debug("UserService.update id={} email={}", id, req.email());
        User u = users.findById(id).orElseThrow(() -> new NotFoundException("User not found"));
        String email = req.email().trim().toLowerCase();
        if (!email.equals(u.getEmail()) && users.existsByEmailNormalized(email))
            throw new DataIntegrityViolationException("Email already in use");

        u.setFirstName(req.firstName());
        u.setLastName(req.lastName());
        u.setEmail(email);
        u.setRoles(fetchRoles(req.roles()));
        return mapper.toDTO(users.save(u));
    }

    @PreAuthorize("hasRole('ADMIN')")
    public void delete(Long id) {
        log.debug("UserService.delete id={}", id);
        if (!users.existsById(id)) throw new NotFoundException("User not found");
        users.deleteById(id);
    }

    private Set<Role> fetchRoles(Set<String> codes) {
        return codes.stream()
                .map(code -> roles.findByCode(code).orElseThrow(() -> new NotFoundException("Role not found: " + code)))
                .collect(Collectors.toSet());
    }
}