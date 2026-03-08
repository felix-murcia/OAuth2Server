package com.oauth.rest.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Arrays;
import java.util.Map;

@Component
@Order(0)
public class ClientIdExtractorFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(ClientIdExtractorFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                   HttpServletResponse response, 
                                   FilterChain filterChain) throws ServletException, IOException {
        
        String uri = request.getRequestURI();
        String method = request.getMethod();
        
        // Procesar tanto GET como POST para /login
        if ("/login".equals(uri)) {
            
            log.info("========== CLIENT ID EXTRACTOR FILTER ==========");
            log.info("Procesando {} /login", method);
            
            // Log todos los parámetros recibidos
            Map<String, String[]> parameterMap = request.getParameterMap();
            log.info("Parámetros recibidos ({}):", parameterMap.size());
            for (Map.Entry<String, String[]> entry : parameterMap.entrySet()) {
                log.info("  - {}: {}", entry.getKey(), Arrays.toString(entry.getValue()));
            }
            
            // 🔴 CAPTURAR TODOS LOS PARÁMETROS IMPORTANTES
            String clientId = request.getParameter("client_id");
            String redirectUri = request.getParameter("redirect_uri");
            String codeChallenge = request.getParameter("code_challenge");
            String state = request.getParameter("state");
            
            log.info("📌 Parámetros específicos:");
            log.info("  - client_id: '{}'", clientId);
            log.info("  - redirect_uri: '{}'", redirectUri);
            log.info("  - code_challenge: '{}'", codeChallenge);
            log.info("  - state: '{}'", state);
            
            // 🔴 GUARDAR EN SESIÓN PARA GET (todos los parámetros)
            if ("GET".equalsIgnoreCase(method)) {
                HttpSession session = request.getSession(true);
                
                if (clientId != null && !clientId.isEmpty()) {
                    session.setAttribute("CLIENT_ID", clientId);
                    log.info("✅ CLIENT_ID guardado en sesión desde GET: {}", clientId);
                }
                
                if (redirectUri != null && !redirectUri.isEmpty()) {
                    session.setAttribute("REDIRECT_URI", redirectUri);
                    log.info("✅ REDIRECT_URI guardado en sesión desde GET: {}", redirectUri);
                }
                
                if (codeChallenge != null && !codeChallenge.isEmpty()) {
                    session.setAttribute("CODE_CHALLENGE", codeChallenge);
                    log.info("✅ CODE_CHALLENGE guardado en sesión desde GET");
                }
                
                if (state != null && !state.isEmpty()) {
                    session.setAttribute("STATE", state);
                    log.info("✅ STATE guardado en sesión desde GET: {}", state);
                }
            }
            
            // 🔴 PARA POST, RECUPERAR DE SESIÓN
            if ("POST".equalsIgnoreCase(method)) {
                HttpSession session = request.getSession(false);
                
                if (session != null) {
                    // Recuperar client_id si no viene en parámetros
                    if (clientId == null || clientId.isEmpty()) {
                        clientId = (String) session.getAttribute("CLIENT_ID");
                        log.info("📌 client_id recuperado de sesión: '{}'", clientId);
                    }
                    
                    // Recuperar redirect_uri (siempre de sesión, no suele venir en POST)
                    redirectUri = (String) session.getAttribute("REDIRECT_URI");
                    log.info("📌 redirect_uri recuperado de sesión: '{}'", redirectUri);
                }
                
                // Guardar en request attribute para el resto de la cadena
                if (clientId != null && !clientId.isEmpty()) {
                    request.setAttribute("CLIENT_ID", clientId);
                    log.info("✅ CLIENT_ID guardado en request attribute: {}", clientId);
                } else {
                    log.error("❌ No se encontró client_id en ninguna parte");
                    log.error("❌ No se puede procesar login sin client_id");
                }
                
                if (redirectUri != null && !redirectUri.isEmpty()) {
                    request.setAttribute("REDIRECT_URI", redirectUri);
                    log.info("✅ REDIRECT_URI guardado en request attribute: {}", redirectUri);
                } else {
                    log.warn("⚠️ No hay redirect_uri, se usará el comportamiento por defecto");
                }
            }
            
            log.info("================================================");
        }
        
        filterChain.doFilter(request, response);
    }
}