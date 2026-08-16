package com.oauth.domain;

import java.util.Optional;

public record UserDomain(
        Long id,
        String username,
        String password,
        String email,
        String fullName,
        String role,
        boolean enabled,
        boolean accountNonExpired,
        boolean accountNonLocked,
        boolean credentialsNonExpired,
        String createdAt,
        String updatedAt) {

    public UserDomain {
        if (Optional.ofNullable(username).isEmpty()) {
            throw new IllegalArgumentException("Username cannot be null or empty");
        }
        if (Optional.ofNullable(password).isEmpty()) {
            throw new IllegalArgumentException("Password cannot be null or empty");
        }
        if (Optional.ofNullable(email).isEmpty()) {
            throw new IllegalArgumentException("Email cannot be null or empty");
        }
        if (Optional.ofNullable(fullName).isEmpty()) {
            throw new IllegalArgumentException("Full name cannot be null or empty");
        }
        if (Optional.ofNullable(role).isEmpty()) {
            throw new IllegalArgumentException("Role cannot be null or empty");
        }
        if (Optional.ofNullable(createdAt).isEmpty()) {
            throw new IllegalArgumentException("Created at cannot be null or empty");
        }
        if (Optional.ofNullable(updatedAt).isEmpty()) {
            throw new IllegalArgumentException("Updated at cannot be null or empty");
        }
    }
}
