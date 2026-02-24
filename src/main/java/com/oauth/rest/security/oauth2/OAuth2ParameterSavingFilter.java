package com.oauth.rest.security.oauth2;

import java.io.IOException;

import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Filtro que guarda los parámetros OAuth2 en una cookie antes de que Spring
 * Security
 * redirija a /login. Esto permite que el AuthenticationSuccessHandler los
 * recupere
 * después del login exitoso.
 */
@Component
public class OAuth2ParameterSavingFilter extends OncePerRequestFilter {

    private static final int COOKIE_MAX_AGE = 300; // 5 minutos

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // Solo procesar solicitudes al endpoint de autorización OAuth2
        String requestUri = request.getRequestURI();
        if (requestUri.endsWith("/oauth2/authorize") || requestUri.endsWith("/oauth/authorize")) {

            String responseType = request.getParameter("response_type");
            String redirectUri = request.getParameter("redirect_uri");
            String clientId = request.getParameter("client_id");
            String state = request.getParameter("state");

            // Solo guardar si es una solicitud de código de autorización
            if ("code".equals(responseType) && (redirectUri != null || clientId != null)) {

                // Guardar en cookies (persistentes entre sesiones)
                if (redirectUri != null && !redirectUri.isBlank()) {
                    addCookie(response, "OAUTH2_REDIRECT_URI", redirectUri);
                }
                if (clientId != null && !clientId.isBlank()) {
                    addCookie(response, "OAUTH2_CLIENT_ID", clientId);
                }
                if (state != null && !state.isBlank()) {
                    addCookie(response, "OAUTH2_STATE", state);
                }
            }
        }

        filterChain.doFilter(request, response);
    }

    private void addCookie(HttpServletResponse response, String name, String value) {
        Cookie cookie = new Cookie(name, value);
        cookie.setPath("/");
        cookie.setHttpOnly(false);
        cookie.setMaxAge(COOKIE_MAX_AGE);
        cookie.setSecure(false);
        response.addCookie(cookie);
    }
}
