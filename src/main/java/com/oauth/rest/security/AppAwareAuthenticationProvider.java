package com.oauth.rest.security;

import com.oauth.rest.security.dto.ApplicationDetails;
import com.oauth.rest.service.CustomUserDetailsService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import jakarta.annotation.PostConstruct;

@Component
public class AppAwareAuthenticationProvider implements AuthenticationProvider {

    private static final Logger log = LoggerFactory.getLogger(AppAwareAuthenticationProvider.class);

    private final CustomUserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    public AppAwareAuthenticationProvider(
            CustomUserDetailsService userDetailsService,
            PasswordEncoder passwordEncoder) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    @PostConstruct
    public void init() {
        log.info("✅✅✅ AppAwareAuthenticationProvider INITIALIZED - HashCode: {}", this.hashCode());
        log.info("   - userDetailsService: {}", userDetailsService.getClass().getName());
        log.info("   - passwordEncoder: {}", passwordEncoder.getClass().getName());
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        
        // ========== LOG DETALLADO DE LA AUTENTICACIÓN ==========
        log.info("========== AUTHENTICATION ATTEMPT ==========");
        log.info("Timestamp: {}", java.time.Instant.now());
        log.info("Authentication class: {}", authentication.getClass().getName());
        log.info("Principal class: {}", 
            authentication.getPrincipal() != null ? authentication.getPrincipal().getClass().getName() : "null");
        log.info("Principal: {}", authentication.getPrincipal());
        log.info("Credentials present: {}", authentication.getCredentials() != null);
        
        String username = authentication.getName();
        String password = authentication.getCredentials() != null ? 
            authentication.getCredentials().toString() : "null";
        
        log.info("Username: '{}'", username);
        log.info("Password length: {}", password.length());
        log.info("Password (first 3 chars): {}***", 
            password.length() > 3 ? password.substring(0, 3) : password);
        
        // ========== DETALLES DE AUTENTICACIÓN ==========
        Object details = authentication.getDetails();
        log.info("Details class: {}", details != null ? details.getClass().getName() : "null");
        
        if (details != null) {
            log.info("Details toString: {}", details.toString());
            
            // Si es ApplicationDetails, mostrar su contenido
            if (details instanceof ApplicationDetails appDetails) {
                log.info("✅ ApplicationDetails found - clientId: '{}'", appDetails.getClientId());
            }
            
            // Si es un Map, mostrar todas las keys
            if (details instanceof java.util.Map) {
                java.util.Map<?, ?> map = (java.util.Map<?, ?>) details;
                log.info("Map details keys: {}", map.keySet());
                map.forEach((k, v) -> log.info("   - {}: {}", k, v));
            }
        }
        
        // ========== EXTRACCIÓN DE CLIENT_ID ==========
        String application = extractClientId(authentication);
        log.info("Extracted application/client_id: '{}'", application);

        try {
            // ========== BÚSQUEDA DE USUARIO ==========
            UserDetails user;
            if (StringUtils.hasText(application)) {
                log.info("🔍 Buscando usuario para aplicación específica: '{}'", application);
                try {
                    user = userDetailsService.loadUserByUsernameAndApplication(username, application);
                    log.info("✅ Usuario encontrado para aplicación específica");
                } catch (UsernameNotFoundException e) {
                    log.error("❌ Usuario no encontrado para aplicación '{}': {}", application, e.getMessage());
                    throw e;
                }
            } else {
                log.info("🔍 Buscando usuario global (sin aplicación)");
                try {
                    user = userDetailsService.loadUserByUsername(username);
                    log.info("✅ Usuario global encontrado");
                } catch (UsernameNotFoundException e) {
                    log.error("❌ Usuario global no encontrado: {}", e.getMessage());
                    throw e;
                }
            }

            // ========== DATOS DEL USUARIO ENCONTRADO ==========
            log.info("📊 User details from DB:");
            log.info("   - Username: {}", user.getUsername());
            log.info("   - Password hash: {}...", 
                user.getPassword() != null ? user.getPassword().substring(0, Math.min(20, user.getPassword().length())) : "null");
            log.info("   - Password hash length: {}", user.getPassword() != null ? user.getPassword().length() : 0);
            log.info("   - Authorities: {}", user.getAuthorities());
            log.info("   - Account non-expired: {}", user.isAccountNonExpired());
            log.info("   - Account non-locked: {}", user.isAccountNonLocked());
            log.info("   - Credentials non-expired: {}", user.isCredentialsNonExpired());
            log.info("   - Enabled: {}", user.isEnabled());

            // ========== VALIDACIÓN DE PASSWORD ==========
            log.info("🔐 Validando password...");
            boolean passwordMatches = passwordEncoder.matches(password, user.getPassword());
            log.info("   - Password matches: {}", passwordMatches);
            
            if (!passwordMatches) {
                log.warn("❌ PASSWORD NO COINCIDE para usuario: '{}'", username);
                
                // Información adicional para debug
                log.warn("   - Raw password provided: '{}'", password);
                log.warn("   - Stored hash: '{}'", user.getPassword());
                
                // Verificar el encoder
                log.warn("   - PasswordEncoder type: {}", passwordEncoder.getClass().getSimpleName());
                
                throw new BadCredentialsException("Invalid credentials");
            }

            log.info("✅ Autenticación exitosa para usuario: '{}' en aplicación: '{}'", username, application);
            
            // ========== CREACIÓN DEL TOKEN AUTENTICADO ==========
            UsernamePasswordAuthenticationToken authenticatedToken = 
                new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
            authenticatedToken.setDetails(authentication.getDetails());
            
            log.info("✅ Token de autenticación creado exitosamente");
            log.info("============================================");
            
            return authenticatedToken;

        } catch (UsernameNotFoundException e) {
            log.error("❌ Usuario no encontrado: '{}' para aplicación: '{}' - {}", username, application, e.getMessage());
            log.info("============================================");
            throw new BadCredentialsException("Invalid credentials");
        } catch (Exception e) {
            log.error("❌ Error inesperado durante autenticación: {}", e.getMessage(), e);
            log.info("============================================");
            throw new BadCredentialsException("Authentication failed: " + e.getMessage());
        }
    }

    private String extractClientId(Authentication authentication) {
        Object details = authentication.getDetails();
        
        // Caso 1: Es ApplicationDetails
        if (details instanceof ApplicationDetails appDetails) {
            String clientId = appDetails.getClientId();
            log.debug("✅ Extracted clientId from ApplicationDetails: '{}'", clientId);
            return clientId;
        }
        
        // Caso 2: Es un Map (posiblemente de Spring)
        if (details instanceof java.util.Map) {
            java.util.Map<?, ?> map = (java.util.Map<?, ?>) details;
            Object clientId = map.get("client_id");
            if (clientId != null) {
                log.debug("✅ Extracted clientId from Map: '{}'", clientId);
                return clientId.toString();
            }
        }
        
        // Caso 3: Es un String
        if (details instanceof String) {
            log.debug("⚠️ Details is a String, not ApplicationDetails: '{}'", details);
            // Podría ser el client_id directamente
            return (String) details;
        }
        
        log.debug("❌ No se pudo extraer clientId. Details class: {}", 
            details != null ? details.getClass().getName() : "null");
        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        boolean supports = UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
        log.debug("🔧 AppAwareAuthenticationProvider.supports({}) = {}", authentication.getSimpleName(), supports);
        return supports;
    }
}