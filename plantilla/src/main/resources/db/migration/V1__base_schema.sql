--------------------------------------------------------------------------------
-- V1: Esquema completo inicial con UUID (PostgreSQL)
--------------------------------------------------------------------------------

-- Habilitar extensión para generar UUIDs
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- =============================================================================
-- TABLAS BASE
-- =============================================================================

-- Tabla de roles
CREATE TABLE roles
(
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),  -- ✅ UUID
    code        VARCHAR(64)              NOT NULL,
    name        VARCHAR(128)             NOT NULL,
    description VARCHAR(512),
    is_system   BOOLEAN                  DEFAULT FALSE NOT NULL,
    created_at  TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    created_by  VARCHAR(128),
    updated_at  TIMESTAMP WITH TIME ZONE,
    updated_by  VARCHAR(128),
    CONSTRAINT uk_roles_code UNIQUE (code)
);

-- Tabla de usuarios
CREATE TABLE users
(
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),  -- ✅ UUID
    first_name    VARCHAR(60)              NOT NULL,
    last_name     VARCHAR(60)              NOT NULL,
    email         VARCHAR(320)             NOT NULL,
    email_norm    VARCHAR(320) GENERATED ALWAYS AS (LOWER(TRIM(email))) STORED,
    password_hash VARCHAR(255)             NOT NULL,
    enabled       BOOLEAN                  DEFAULT TRUE NOT NULL,
    locked        BOOLEAN                  DEFAULT FALSE NOT NULL,
    mfa_enabled   BOOLEAN                  DEFAULT FALSE NOT NULL,
    last_login_at TIMESTAMP WITH TIME ZONE,
    created_at    TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    created_by    VARCHAR(128),
    updated_at    TIMESTAMP WITH TIME ZONE,
    updated_by    VARCHAR(128),
    deleted_at    TIMESTAMP WITH TIME ZONE,
    CONSTRAINT uk_users_email_norm UNIQUE (email_norm)
);

-- Índices adicionales para usuarios
CREATE INDEX ix_users_email ON users (email);
CREATE INDEX ix_users_created_at ON users (created_at);
CREATE INDEX ix_users_deleted_at ON users (deleted_at) WHERE deleted_at IS NOT NULL;

-- Relación muchos-a-muchos usuario <-> roles
CREATE TABLE user_roles
(
    user_id UUID NOT NULL,  -- ✅ UUID
    role_id UUID NOT NULL,  -- ✅ UUID
    CONSTRAINT pk_user_roles PRIMARY KEY (user_id, role_id),
    CONSTRAINT fk_user_roles_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT fk_user_roles_role FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE
);

CREATE INDEX ix_user_roles_user ON user_roles (user_id);
CREATE INDEX ix_user_roles_role ON user_roles (role_id);

-- Tabla de logs de solicitud
CREATE TABLE request_logs
(
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),  -- ✅ UUID
    user_id     UUID,  -- ✅ UUID
    email       VARCHAR(320),
    method      VARCHAR(10)              NOT NULL,
    path        VARCHAR(512)             NOT NULL,
    status_code INTEGER                  NOT NULL,
    success     BOOLEAN                  DEFAULT TRUE NOT NULL,
    ip_address  VARCHAR(45),
    user_agent  VARCHAR(512),
    occurred_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT fk_request_logs_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
);

CREATE INDEX ix_request_logs_user ON request_logs (user_id);
CREATE INDEX ix_request_logs_path ON request_logs (path);
CREATE INDEX ix_request_logs_time ON request_logs (occurred_at);
CREATE INDEX ix_request_logs_status ON request_logs (status_code);

-- Tabla de tokens revocados (JWT blacklist)
CREATE TABLE revoked_tokens
(
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),  -- ✅ UUID
    jti        VARCHAR(64)              NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    reason     VARCHAR(255),
    CONSTRAINT uk_revoked_tokens_jti UNIQUE (jti)
);

CREATE INDEX ix_revoked_tokens_jti ON revoked_tokens (jti);
CREATE INDEX ix_revoked_tokens_revoked_at ON revoked_tokens (revoked_at);

-- Tabla de sesiones de usuario (refresh tokens)
CREATE TABLE user_sessions
(
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),  -- ✅ UUID
    user_id          UUID                     NOT NULL,  -- ✅ UUID
    refresh_token_id VARCHAR(64)              NOT NULL,
    refresh_hash     VARCHAR(255)             NOT NULL,
    access_jti       VARCHAR(64),
    issued_at        TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at       TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked_at       TIMESTAMP WITH TIME ZONE,
    revoked_reason   VARCHAR(255),
    ip_address       VARCHAR(45),
    user_agent       VARCHAR(512),
    last_seen_at     TIMESTAMP WITH TIME ZONE,
    CONSTRAINT uk_user_sessions_refresh UNIQUE (refresh_token_id),
    CONSTRAINT fk_user_sessions_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX ix_user_sessions_user ON user_sessions (user_id);
CREATE INDEX ix_user_sessions_expires ON user_sessions (expires_at);
CREATE INDEX ix_user_sessions_revoked ON user_sessions (revoked_at);
CREATE INDEX ix_user_sessions_access_jti ON user_sessions (access_jti);

-- =============================================================================
-- DATOS INICIALES
-- =============================================================================

-- Roles por defecto
INSERT INTO roles (code, name, description, is_system, created_by)
VALUES ('ADMIN', 'Administrador', 'Acceso completo al sistema', TRUE, 'SYSTEM'),
       ('USER', 'Usuario', 'Acceso básico al sistema', TRUE, 'SYSTEM');

-- Usuario administrador por defecto
-- Contraseña: admin123 (encriptada con BCrypt)
INSERT INTO users (first_name, last_name, email, password_hash, enabled, locked, mfa_enabled, created_by)
VALUES ('Admin',
        'Root',
        'admin@example.com',
        '$2a$12$M4rhBfD9cB1prGzA30oUiummizeP/DNIR.h0dQ38K6za73h1kVG2C',
        TRUE,
        FALSE,
        FALSE,
        'SYSTEM');

-- Asignar rol ADMIN al usuario administrador
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id
FROM users u
         CROSS JOIN roles r
WHERE u.email_norm = 'admin@example.com'
  AND r.code = 'ADMIN';

-- =============================================================================
-- COMENTARIOS EN TABLAS (Opcional - para documentación)
-- =============================================================================

COMMENT ON TABLE roles IS 'Catálogo de roles del sistema';
COMMENT ON TABLE users IS 'Usuarios del sistema';
COMMENT ON TABLE user_roles IS 'Relación muchos-a-muchos entre usuarios y roles';
COMMENT ON TABLE request_logs IS 'Log de peticiones HTTP para auditoría';
COMMENT ON TABLE revoked_tokens IS 'Tokens JWT revocados (blacklist)';
COMMENT ON TABLE user_sessions IS 'Sesiones activas de usuarios con refresh tokens';

COMMENT ON COLUMN users.email_norm IS 'Email normalizado (lowercase, trimmed) para búsquedas case-insensitive';
COMMENT ON COLUMN roles.is_system IS 'Indica si es un rol del sistema que no puede ser eliminado';