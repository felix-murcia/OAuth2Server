package com.oauth.infrastructure.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;

import com.oauth.infrastructure.output.security.AppAwareAuthenticationProvider;

@Configuration
public class AuthenticationManagerConfig {

    private final AppAwareAuthenticationProvider appAwareAuthenticationProvider;

    public AuthenticationManagerConfig(
            AppAwareAuthenticationProvider appAwareAuthenticationProvider) {
        this.appAwareAuthenticationProvider = appAwareAuthenticationProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        // Usar SOLO tu provider personalizado
        return new ProviderManager(appAwareAuthenticationProvider);
    }
}