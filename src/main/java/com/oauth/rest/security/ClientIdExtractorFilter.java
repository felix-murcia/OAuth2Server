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
                                    
            String clientId = request.getParameter("client_id");
            String redirectUri = request.getParameter("redirect_uri");
            String codeChallenge = request.getParameter("code_challenge");
            String state = request.getParameter("state");
            
            if ("GET".equalsIgnoreCase(method)) {
                HttpSession session = request.getSession(true);
                
                if (clientId != null && !clientId.isEmpty()) {
                    session.setAttribute("CLIENT_ID", clientId);
                }
                
                if (redirectUri != null && !redirectUri.isEmpty()) {
                    session.setAttribute("REDIRECT_URI", redirectUri);
                }
                
                if (codeChallenge != null && !codeChallenge.isEmpty()) {
                    session.setAttribute("CODE_CHALLENGE", codeChallenge);
                }
                
                if (state != null && !state.isEmpty()) {
                    session.setAttribute("STATE", state);
                }
            }
            
            if ("POST".equalsIgnoreCase(method)) {
                HttpSession session = request.getSession(false);
                
                if (session != null) {
                    // Recuperar client_id si no viene en parámetros
                    if (clientId == null || clientId.isEmpty()) {
                        clientId = (String) session.getAttribute("CLIENT_ID");
                    }
                    
                    // Recuperar redirect_uri (siempre de sesión, no suele venir en POST)
                    redirectUri = (String) session.getAttribute("REDIRECT_URI");
                }
                
                // Guardar en request attribute para el resto de la cadena
                if (clientId != null && !clientId.isEmpty()) {
                    request.setAttribute("CLIENT_ID", clientId);
                } else {
                    log.debug("No se puede procesar login sin client_id");
                }
                
                if (redirectUri != null && !redirectUri.isEmpty()) {
                    request.setAttribute("REDIRECT_URI", redirectUri);
                } else {
                    log.debug("No hay redirect_uri, se usará el comportamiento por defecto");
                }
            }
        }
        
        filterChain.doFilter(request, response);
    }
}