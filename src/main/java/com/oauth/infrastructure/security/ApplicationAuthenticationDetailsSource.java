package com.oauth.infrastructure.security;

import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.stereotype.Component;

import com.oauth.infrastructure.output.database.dto.ApplicationDetailsDTO;

import jakarta.servlet.http.HttpServletRequest;

@Component
public class ApplicationAuthenticationDetailsSource
        implements AuthenticationDetailsSource<HttpServletRequest, ApplicationDetailsDTO> {

    @Override
    public ApplicationDetailsDTO buildDetails(HttpServletRequest context) {
        String clientId = (String) context.getAttribute("CLIENT_ID");
        return new ApplicationDetailsDTO(clientId);
    }
}
