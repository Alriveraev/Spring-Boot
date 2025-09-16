package com.sprintboot.webapp.plantilla.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.servers.Server;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

@Profile("dev") // Solo estará disponible en el perfil 'dev'
@OpenAPIDefinition(
        info = @Info(
                title = "MV Proyect API",
                version = "${app.version:0.3.0}",
                description = "API con Oracle + JWT + Flyway | Módulos: Auth, Users"
        ),
        servers = {
                @Server(url = "/", description = "Local")
        },
        security = @SecurityRequirement(name = "bearerAuth")
)
@SecurityScheme(
        name = "bearerAuth",
        type = SecuritySchemeType.HTTP,   // Enum correcto
        scheme = "bearer",
        bearerFormat = "JWT"
)
@Configuration
public class OpenAPIConfig {

    @Bean
    GroupedOpenApi authGroup() {
        return GroupedOpenApi.builder()
                .group("auth")
                .packagesToScan("com.sprintboot.webapp.plantilla.modules.auth.api")
                .build();
    }

    @Bean
    GroupedOpenApi usersGroup() {
        return GroupedOpenApi.builder()
                .group("users")
                .packagesToScan("com.sprintboot.webapp.plantilla.modules.users.api")
                .build();
    }
}
