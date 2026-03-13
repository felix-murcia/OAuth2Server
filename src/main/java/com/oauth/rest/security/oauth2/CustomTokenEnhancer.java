package com.oauth.rest.security.oauth2;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.core.GrantedAuthority;

import java.util.Set;
import java.util.stream.Collectors;

import com.oauth.rest.model.UserEntity;
import com.oauth.rest.service.UserEntityService;

@Configuration
@Slf4j
public class CustomTokenEnhancer {

    private final UserEntityService userService;

    public CustomTokenEnhancer(UserEntityService userService) {
        this.userService = userService;
        log.info("✅ CustomTokenEnhancer bean creado");
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
        return context -> {
            log.info("=== INICIO CUSTOMIZER ===");
            log.info("Token type: {}", context.getTokenType().getValue());
            log.info("Grant type: {}", context.getAuthorizationGrantType().getValue());
            
            // Solo procesar access tokens
            if (!"access_token".equals(context.getTokenType().getValue())) {
                log.info("No es access_token, saliendo");
                return;
            }

            String username = context.getPrincipal().getName();
            log.info("Username del principal: {}", username);
            
            // Buscar usuario
            UserEntity user = userService.findUserByUsername(username).orElse(null);
            
            if (user != null) {
                log.info("Usuario encontrado! ID: {}, Email: {}, FullName: {}", 
                    user.getId(), user.getEmail(), user.getFullName());
                
                String email = user.getEmail();
                String name = user.getFullName() != null ? user.getFullName() : username;
                
                // Añadir claims directamente
                context.getClaims().claim("sub", email);
                context.getClaims().claim("email", email);
                context.getClaims().claim("name", name);
                
                log.info("Claims a\u00f1adidos: sub={}, email={}, name={}", email, email, name);
            } else {
                log.warn("Usuario NO encontrado en BD!");
            }
            
            // Añadir roles
            Set<String> authorities = context.getPrincipal().getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toSet());
            context.getClaims().claim("roles", authorities);
            
            log.info("=== FIN CUSTOMIZER ===");
        };
    }
}
