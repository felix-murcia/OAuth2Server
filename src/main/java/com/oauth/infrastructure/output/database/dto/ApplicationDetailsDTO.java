package com.oauth.infrastructure.output.database.dto;

/**
 * Value object para detalles de autenticación específicos de aplicación
 * Record inmutable para clientId
 */
public record ApplicationDetailsDTO(String clientId) {

    @Override
    public String toString() {
        return String.format("ApplicationDetails{clientId='%s'}", clientId());
    }
}
