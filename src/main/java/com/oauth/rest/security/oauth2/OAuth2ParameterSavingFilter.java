package com.oauth.rest.security.oauth2;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

/**
 * Filtro que guarda los parámetros OAuth2 en cookie y sesión antes de que
 * Spring Security
 * redirija a /login. Esto permite que el AuthenticationSuccessHandler los
 * recupere
 * después del login exitoso.
 */
@Component
public class OAuth2ParameterSavingFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(OAuth2ParameterSavingFilter.class);
    private static final int COOKIE_MAX_AGE = 300; // 5 minutos

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // Solo procesar solicitudes al endpoint de autorización OAuth2
        String requestUri = request.getRequestURI();
        log.info("[OAuth2ParameterSavingFilter] Request URI: {}", requestUri);

        if (requestUri.endsWith("/oauth2/authorize") || requestUri.endsWith("/oauth/authorize")) {

            String responseType = request.getParameter("response_type");
            String redirectUri = request.getParameter("redirect_uri");
            String clientId = request.getParameter("client_id");
            String state = request.getParameter("state");
            String scope = request.getParameter("scope");

            log.info(
                    "[OAuth2ParameterSavingFilter] OAuth2 params - response_type: {}, client_id: {}, redirect_uri: {}, state: {}, scope: {}",
                    responseType, clientId, redirectUri, state, scope);

            // Solo guardar si es una solicitud de código de autorización
            if ("code".equals(responseType) && (redirectUri != null || clientId != null)) {

                // Guardar en sesión (más seguro y funciona entre dominios si la sesión es
                // compartida)
                HttpSession session = request.getSession(true);

                if (redirectUri != null && !redirectUri.isBlank()) {
                    session.setAttribute("OAUTH2_REDIRECT_URI", redirectUri);
                    log.info("[OAuth2ParameterSavingFilter] Saved OAUTH2_REDIRECT_URI in session");
                }
                if (clientId != null && !clientId.isBlank()) {
                    session.setAttribute("OAUTH2_CLIENT_ID", clientId);
                    log.info("[OAuth2ParameterSavingFilter] Saved OAUTH2_CLIENT_ID in session");
                }
                if (state != null && !state.isBlank()) {
                    session.setAttribute("OAUTH2_STATE", state);
                    log.info("[OAuth2ParameterSavingFilter] Saved OAUTH2_STATE in session");
                }
                if (scope != null && !scope.isBlank()) {
                    session.setAttribute("OAUTH2_SCOPE", scope);
                    log.info("[OAuth2ParameterSavingFilter] Saved OAUTH2_SCOPE in session");
                }
                if (responseType != null && !responseType.isBlank()) {
                    session.setAttribute("OAUTH2_RESPONSE_TYPE", responseType);
                    log.info("[OAuth2ParameterSavingFilter] Saved OAUTH2_RESPONSE_TYPE in session");
                }

                // Guardar también parámetros PKCE
                String codeChallenge = request.getParameter("code_challenge");
                String codeChallengeMethod = request.getParameter("code_challenge_method");
                log.info("[OAuth2ParameterSavingFilter] PKCE params - code_challenge: {}, code_challenge_method: {}",
                        codeChallenge, codeChallengeMethod);

                if (codeChallenge != null && !codeChallenge.isBlank()) {
                    session.setAttribute("OAUTH2_CODE_CHALLENGE", codeChallenge);
                    log.info("[OAuth2ParameterSavingFilter] Saved OAUTH2_CODE_CHALLENGE in session");
                }
                if (codeChallengeMethod != null && !codeChallengeMethod.isBlank()) {
                    session.setAttribute("OAUTH2_CODE_CHALLENGE_METHOD", codeChallengeMethod);
                    log.info("[OAuth2ParameterSavingFilter] Saved OAUTH2_CODE_CHALLENGE_METHOD in session");
                }

                // También guardar en cookies como fallback (para compatibilidad)
                if (redirectUri != null && !redirectUri.isBlank()) {
                    addCookie(response, "OAUTH2_REDIRECT_URI", urlEncode(redirectUri));
                }
                if (clientId != null && !clientId.isBlank()) {
                    addCookie(response, "OAUTH2_CLIENT_ID", urlEncode(clientId));
                }
                if (state != null && !state.isBlank()) {
                    addCookie(response, "OAUTH2_STATE", urlEncode(state));
                }
                if (scope != null && !scope.isBlank()) {
                    addCookie(response, "OAUTH2_SCOPE", urlEncode(scope));
                }
                if (responseType != null && !responseType.isBlank()) {
                    addCookie(response, "OAUTH2_RESPONSE_TYPE", urlEncode(responseType));
                }
                if (codeChallenge != null && !codeChallenge.isBlank()) {
                    addCookie(response, "OAUTH2_CODE_CHALLENGE", urlEncode(codeChallenge));
                }
                if (codeChallengeMethod != null && !codeChallengeMethod.isBlank()) {
                    addCookie(response, "OAUTH2_CODE_CHALLENGE_METHOD", urlEncode(codeChallengeMethod));
                }

                log.info("[OAuth2ParameterSavingFilter] All OAuth2 parameters saved in session and cookies");
            } else {
                log.warn(
                        "[OAuth2ParameterSavingFilter] Not saving params - response_type is not 'code' or no client_id/redirect_uri");
            }
        }

        filterChain.doFilter(request, response);
    }

    private void addCookie(HttpServletResponse response, String name, String value) {
        Cookie cookie = new Cookie(name, value);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setMaxAge(COOKIE_MAX_AGE);
        cookie.setSecure(true);
        cookie.setAttribute("SameSite", "Lax");
        response.addCookie(cookie);
    }

    private String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}