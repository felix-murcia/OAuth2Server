package com.oauth.rest.security;

import com.oauth.rest.service.CustomUserDetailsService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import jakarta.servlet.http.HttpServletRequest;

/**
 * AuthenticationProvider que filtra usuarios por aplicación
 * Usa el client_id de la solicitud OAuth2 para determinar la aplicación
 */
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

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();

        // Obtener la aplicación del contexto
        String application = obtenerApplicationDelContexto();

        log.debug("Autenticando usuario: {} para aplicación: {}", username, application);

        if (application == null) {
            // Fallback: buscar sin filtro de aplicación (compatibilidad hacia atrás)
            log.debug("No se encontró aplicación en el contexto, usando fallback");
            UserDetails user = userDetailsService.loadUserByUsername(username);
            if (!passwordEncoder.matches(password, user.getPassword())) {
                log.warn("Credenciales incorrectas para usuario: {} (fallback)", username);
                throw new BadCredentialsException("Credenciales incorrectas");
            }
            log.info("Usuario autenticado correctamente (fallback): {}", username);
            return new UsernamePasswordAuthenticationToken(
                    user, null, user.getAuthorities());
        }

        // Buscar usuario filtrado por aplicación
        try {
            UserDetails user = userDetailsService.loadUserByUsernameAndApplication(username, application);

            if (!passwordEncoder.matches(password, user.getPassword())) {
                log.warn("Credenciales incorrectas para usuario: {} en aplicación: {}", username, application);
                throw new BadCredentialsException("Credenciales incorrectas");
            }

            log.info("Usuario autenticado correctamente: {} en aplicación: {}", username, application);
            return new UsernamePasswordAuthenticationToken(
                    user, null, user.getAuthorities());

        } catch (Exception e) {
            log.error("Error al autenticar usuario: {} en aplicación: {} - {}", username, application, e.getMessage());
            throw new BadCredentialsException("Error en la autenticación: " + e.getMessage());
        }
    }

    /**
     * Obtiene la aplicación del contexto de seguridad
     * Busca en: request attribute, sesión, y finalmente SecurityContextHolder
     */
    private String obtenerApplicationDelContexto() {
        try {
            // 1. Intentar obtener de la request actual
            ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder
                    .getRequestAttributes();
            if (attributes != null) {
                HttpServletRequest request = attributes.getRequest();

                // Buscar en los atributos de la request (establecido por
                // ClientIdExtractorFilter)
                String clientId = (String) request.getAttribute("CLIENT_ID");
                if (clientId != null && !clientId.isEmpty()) {
                    log.debug("Client ID encontrado en request attribute: {}", clientId);
                    return clientId;
                }

                // Buscar en los parámetros de la request (por si el filtro no se ejecutó)
                clientId = request.getParameter("client_id");
                if (clientId != null && !clientId.isEmpty()) {
                    log.debug("Client ID encontrado en request parameter: {}", clientId);
                    return clientId;
                }

                // 2. Intentar obtener de la sesión
                if (request.getSession(false) != null) {
                    clientId = (String) request.getSession().getAttribute("CLIENT_ID");
                    if (clientId != null && !clientId.isEmpty()) {
                        log.debug("Client ID encontrado en sesión: {}", clientId);
                        return clientId;
                    }
                }
            }

            // 3. Intentar obtener del contexto de seguridad
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && auth.getDetails() instanceof String) {
                String clientId = (String) auth.getDetails();
                if (clientId != null && !clientId.isEmpty()) {
                    log.debug("Client ID encontrado en contexto de seguridad: {}", clientId);
                    return clientId;
                }
            }

        } catch (Exception e) {
            log.warn("Error al obtener aplicación del contexto: {}", e.getMessage());
        }

        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}