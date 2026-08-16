package com.oauth.infrastructure.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.core.GrantedAuthority;

import java.util.Set;
import java.util.stream.Collectors;

import com.oauth.infrastructure.input.UserServiceAdapter;

@Configuration
@Slf4j
public class CustomTokenConfig {

    private final UserServiceAdapter userServiceAdapter;

    public CustomTokenConfig(UserServiceAdapter userServiceAdapter) {
        this.userServiceAdapter = userServiceAdapter;
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
        return context -> {

            // Solo procesar access tokens
            if (!"access_token".equals(context.getTokenType().getValue())) {
                log.debug("No es access_token, saliendo");
                return;
            }

            var username = context.getPrincipal().getName();

            // Buscar usuario
            var user = userServiceAdapter.findByUsername(username).orElse(null);

            if (user != null) {
                var email = user.email();
                var name = user.fullName() != null ? user.fullName() : username;

                // Añadir claims directamente
                context.getClaims().claim("sub", email);
                context.getClaims().claim("email", email);
                context.getClaims().claim("name", name);

            } else {
                log.debug("Usuario NO encontrado en BD!");
            }

            // Añadir roles
            Set<String> authorities = context.getPrincipal().getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toSet());
            context.getClaims().claim("roles", authorities);
        };
    }
}
