package com.oauth.rest.security.oauth2;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Set;
import java.util.stream.Collectors;

@Configuration
public class CustomTokenEnhancer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    private static final Logger log = LoggerFactory.getLogger(CustomTokenEnhancer.class);

    @Override
    public void customize(JwtEncodingContext context) {
        if (!"access_token".equals(context.getTokenType().getValue())) {
            return;
        }

        Authentication authentication = context.getPrincipal();
        if (authentication == null) {
            return;
        }

        // Añadir roles directamente (sin filtrar)
        Set<String> authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());

        context.getClaims().claim("roles", authorities);
        
        log.debug("Token customized for user: {} with roles: {}", 
                 authentication.getName(), authorities);
    }
}