package com.oauth.rest.security.oauth2;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import java.util.Arrays;
import org.springframework.beans.factory.annotation.Qualifier;

@Configuration
@EnableAuthorizationServer
public class OAuth2AuthorizationServer extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private CustomTokenEnhancer customTokenEnhancer;

    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    @Value("${oauth2.client-id}")
    private String clientId;

    @Value("${oauth2.client-secret}")
    private String clientSecret;

    @Value("${oauth2.redirect-uri}")
    private String redirectUri;

    @Value("${oauth2.access-token-validity-seconds}")
    private int accessTokenValiditySeconds;

    @Value("${oauth2.refresh-token-validity-seconds}")
    private int refreshTokenValiditySeconds;

    @Value("${oauth2.jwt-signing-key}")
    private String jwtSigningKey;

    public OAuth2AuthorizationServer(
            PasswordEncoder passwordEncoder,
            @Qualifier(BeanIds.AUTHENTICATION_MANAGER) AuthenticationManager authenticationManager) {

        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
    }

    @Bean
    public TokenStore tokenStore() {
        return new JwtTokenStore(accessTokenConverter());
    }

    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setSigningKey(jwtSigningKey);
        return converter;
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) {
        security
                .tokenKeyAccess("permitAll()")
                .checkTokenAccess("isAuthenticated()")
                .allowFormAuthenticationForClients();
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients
                .inMemory()
                .withClient(clientId)
                .secret(passwordEncoder.encode(clientSecret))
                .authorizedGrantTypes("password", "refresh_token", "authorization_code", "implicit")
                .scopes("read", "write")
                .resourceIds("oauth2-resource")
                .redirectUris(redirectUri)
                .accessTokenValiditySeconds(accessTokenValiditySeconds)
                .refreshTokenValiditySeconds(refreshTokenValiditySeconds);
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {

        TokenEnhancerChain enhancerChain = new TokenEnhancerChain();
        enhancerChain.setTokenEnhancers(
                Arrays.asList(customTokenEnhancer, accessTokenConverter()));

        endpoints
                .tokenStore(tokenStore())
                .tokenEnhancer(enhancerChain)
                .accessTokenConverter(accessTokenConverter())
                .authenticationManager(authenticationManager);
    }
}
