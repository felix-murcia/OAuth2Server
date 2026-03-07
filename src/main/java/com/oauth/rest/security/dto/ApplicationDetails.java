package com.oauth.rest.security.dto;

import java.io.Serializable;

/**
 * DTO para detalles de autenticación específicos de aplicación
 * Clase independiente y reutilizable
 */
public class ApplicationDetails implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    private final String clientId;

    public ApplicationDetails(String clientId) {
        this.clientId = clientId;
    }

    public String getClientId() {
        return clientId;
    }
    
    @Override
    public String toString() {
        return String.format("ApplicationDetails{clientId='%s'}", clientId);
    }
}