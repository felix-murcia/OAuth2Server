package com.oauth.infrastructure.config;

import com.oauth.infrastructure.output.database.persistence.ApplicationRepository;
import com.oauth.infrastructure.output.database.ApplicationJpaEntity;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.util.UUID;

@Slf4j
public class JpaRegisteredClientRepository implements RegisteredClientRepository {

    private final ApplicationRepository applicationRepository;
    private final PasswordEncoder passwordEncoder;
    private final int accessTokenValiditySeconds;
    private final int refreshTokenValiditySeconds;

    public JpaRegisteredClientRepository(ApplicationRepository applicationRepository,
            PasswordEncoder passwordEncoder,
            int accessTokenValiditySeconds,
            int refreshTokenValiditySeconds) {
        this.applicationRepository = applicationRepository;
        this.passwordEncoder = passwordEncoder;
        this.accessTokenValiditySeconds = accessTokenValiditySeconds;
        this.refreshTokenValiditySeconds = refreshTokenValiditySeconds;
    }

    @Override
    public void save(RegisteredClient registeredClient) {
        // Secrets are managed via DB migrations; encoding upgrades are intentionally
        // ignored
    }

    @Override
    public RegisteredClient findById(String id) {
        return applicationRepository.findByClientId(id)
                .map(this::toRegisteredClient)
                .orElse(null);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        return applicationRepository.findByClientId(clientId)
                .map(this::toRegisteredClient)
                .orElse(null);
    }

    private RegisteredClient toRegisteredClient(ApplicationJpaEntity app) {
        String encodedSecret = app.getClientSecret();
        if (!encodedSecret.startsWith("{")) {
            encodedSecret = passwordEncoder.encode(encodedSecret);
        }

        var builder = RegisteredClient.withId(UUID.nameUUIDFromBytes(app.getClientId().getBytes()).toString())
                .clientId(app.getClientId())
                .clientSecret(encodedSecret)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("openid")
                .scope("profile")
                .scope("email")
                .scope("read")
                .scope("write")
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false)
                        .requireProofKey(false)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofSeconds(accessTokenValiditySeconds))
                        .refreshTokenTimeToLive(Duration.ofSeconds(refreshTokenValiditySeconds))
                        .reuseRefreshTokens(false)
                        .build());

        if (app.getRedirectUri() != null && !app.getRedirectUri().isBlank()) {
            builder.redirectUri(app.getRedirectUri());
        }

        return builder.build();
    }
}
