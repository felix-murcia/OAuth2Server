package com.oauth.domain;

import java.util.Optional;

public record RoleDomain(
        Long id,
        String name,
        String description,
        String createdAt,
        String updatedAt) {

    public RoleDomain {
        if (Optional.ofNullable(name).isEmpty()) {
            throw new IllegalArgumentException("Name cannot be null or empty");
        }
        if (Optional.ofNullable(description).isEmpty()) {
            throw new IllegalArgumentException("Description cannot be null or empty");
        }
        if (Optional.ofNullable(createdAt).isEmpty()) {
            throw new IllegalArgumentException("Created At cannot be null or empty");
        }
        if (Optional.ofNullable(updatedAt).isEmpty()) {
            throw new IllegalArgumentException("Updated At cannot be null or empty");
        }
    }
}