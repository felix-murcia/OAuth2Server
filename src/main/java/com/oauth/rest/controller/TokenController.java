package com.oauth.rest.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;

/**
 * Controlador personalizado para el endpoint de token OAuth2.
 * Maneja el grant type "password" que fue eliminado en Spring Authorization
 * Server moderno.
 */
@RestController
public class TokenController {

    private final AuthenticationManager authenticationManager;
    private final RegisteredClientRepository registeredClientRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtEncoder jwtEncoder;

    @Value("${oauth2.access-token-validity-seconds:3600}")
    private int accessTokenValiditySeconds;

    @Value("${oauth2.client-id}")
    private String clientId;

    public TokenController(AuthenticationManager authenticationManager,
            RegisteredClientRepository registeredClientRepository,
            PasswordEncoder passwordEncoder,
            JwtEncoder jwtEncoder) {
        this.authenticationManager = authenticationManager;
        this.registeredClientRepository = registeredClientRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtEncoder = jwtEncoder;
    }

    @PostMapping(value = "/oauth/token", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> token(
            @RequestParam("grant_type") String grantType,
            @RequestParam(value = "username", required = false) String username,
            @RequestParam(value = "password", required = false) String password,
            @RequestParam(value = "scope", required = false) String scope,
            @RequestParam(value = "client_id", required = false) String clientIdHeader,
            @RequestParam(value = "client_secret", required = false) String clientSecretHeader) {

        // Verificar grant type password
        if (!"password".equals(grantType)) {
            return error("unsupported_grant_type", "OAuth 2.0 Parameter: grant_type");
        }

        // Verificar cliente
        RegisteredClient client = registeredClientRepository.findByClientId(clientId);
        if (client == null) {
            return error("invalid_client", "Client authentication failed");
        }

        // Verificar credenciales del cliente
        if (clientSecretHeader != null && !passwordEncoder.matches(clientSecretHeader, client.getClientSecret())) {
            return error("invalid_client", "Client authentication failed");
        }

        // Autenticar usuario
        if (username == null || password == null) {
            return error("invalid_request", "Username and password are required");
        }

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password));

            UserDetails userDetails = (UserDetails) authentication.getPrincipal();

            // Generar scopes
            String[] scopesArray = scope != null ? scope.split("\\s+") : new String[0];

            // Generar JWT
            Instant now = Instant.now();
            Instant expiry = now.plus(accessTokenValiditySeconds, ChronoUnit.SECONDS);

            JwtClaimsSet jwtClaimsSet = JwtClaimsSet.builder()
                    .subject(userDetails.getUsername())
                    .issuer("http://localhost:8080")
                    .issuedAt(now)
                    .expiresAt(expiry)
                    .claim("scope", String.join(" ", scopesArray))
                    .build();

            String accessToken = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet)).getTokenValue();

            // Respuesta
            Map<String, Object> response = new HashMap<>();
            response.put("access_token", accessToken);
            response.put("token_type", "Bearer");
            response.put("expires_in", accessTokenValiditySeconds);
            response.put("scope", scope != null ? scope : "read write");

            return response;

        } catch (AuthenticationException e) {
            return error("invalid_grant", "User authentication failed");
        }
    }

    private Map<String, Object> error(String error, String description) {
        Map<String, Object> response = new HashMap<>();
        response.put("error", error);
        response.put("error_description", description);
        response.put("error_uri", "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2");
        return response;
    }
}
