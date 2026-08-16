package com.oauth.domain;

import java.time.LocalDateTime;

public record UserApplicationDomain(Long id, UserDomain usuario, ApplicationDomain application,
        LocalDateTime registeredAt) {

    public UserApplicationDomain {
        if (usuario == null || application == null) {
            throw new IllegalArgumentException("Usuario y aplicación no pueden ser nulos");
        }
        if (id == null) {
            throw new IllegalArgumentException("Id no puede ser nulo");
        }
        if (registeredAt == null) {
            throw new IllegalArgumentException("Fecha de registro no puede ser nula");
        }
    }
}
