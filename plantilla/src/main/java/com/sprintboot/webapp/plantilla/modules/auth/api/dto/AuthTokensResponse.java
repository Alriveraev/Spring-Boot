package com.sprintboot.webapp.plantilla.modules.auth.api.dto;


public record AuthTokensResponse(
        String accessToken,
        long accessExpiresInSeconds,
        String refreshToken,
        long refreshExpiresInSeconds,
        String tokenType
) {
}
