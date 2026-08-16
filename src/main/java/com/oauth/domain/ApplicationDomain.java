package com.oauth.domain;

import java.util.Optional;

public record ApplicationDomain(
        Long id,
        String clientId,
        String clientSecret,
        String name,
        String description,
        String redirectUri,
        String grantType,
        String scope,
        String accessTokenValidity,
        String refreshTokenValidity,
        boolean enabled,
        String createdAt,
        String updatedAt) {

    public ApplicationDomain {
        if (Optional.ofNullable(clientId).isEmpty()) {
            throw new IllegalArgumentException("Client ID cannot be null or empty");
        }
        if (Optional.ofNullable(clientSecret).isEmpty()) {
            throw new IllegalArgumentException("Client Secret cannot be null or empty");
        }
        if (Optional.ofNullable(name).isEmpty()) {
            throw new IllegalArgumentException("Name cannot be null or empty");
        }
        if (Optional.ofNullable(description).isEmpty()) {
            throw new IllegalArgumentException("Description cannot be null or empty");
        }
        if (Optional.ofNullable(redirectUri).isEmpty()) {
            throw new IllegalArgumentException("Redirect URI cannot be null or empty");
        }
        if (Optional.ofNullable(grantType).isEmpty()) {
            throw new IllegalArgumentException("Grant Type cannot be null or empty");
        }
        if (Optional.ofNullable(scope).isEmpty()) {
            throw new IllegalArgumentException("Scope cannot be null or empty");
        }
        if (Optional.ofNullable(accessTokenValidity).isEmpty()) {
            throw new IllegalArgumentException("Access Token Validity cannot be null or empty");
        }
        if (Optional.ofNullable(refreshTokenValidity).isEmpty()) {
            throw new IllegalArgumentException("Refresh Token Validity cannot be null or empty");
        }
        if (Optional.ofNullable(createdAt).isEmpty()) {
            throw new IllegalArgumentException("Created At cannot be null or empty");
        }
        if (Optional.ofNullable(updatedAt).isEmpty()) {
            throw new IllegalArgumentException("Updated At cannot be null or empty");
        }
    }
}
