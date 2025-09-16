--------------------------------------------------------------------------------
-- V2: Datos iniciales
--------------------------------------------------------------------------------

-- Roles por defecto
INSERT INTO roles (code, name, description, is_system)
VALUES ('ADMIN', 'Administrador', 'Acceso completo al sistema', 1);

INSERT INTO roles (code, name, description, is_system)
VALUES ('USER', 'Usuario', 'Acceso limitado', 1);

-- Usuario administrador por defecto (contraseña: admin123 encriptada con BCrypt)
INSERT INTO users (first_name, last_name, email, password_hash, enabled, locked, created_by)
VALUES ('Admin', 'Root', 'admin@example.com',
        '$2a$10$z6VUqHd1FQppF0Vf1n2kGeYhE7stpQlHRYXptx9y3L1j7vXhQru6q', -- BCrypt: admin123
        1, 0, 'SYSTEM');

-- Asignar rol ADMIN al admin
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id
FROM users u,
     roles r
WHERE u.email_norm = 'admin@example.com'
  AND r.code = 'ADMIN';
