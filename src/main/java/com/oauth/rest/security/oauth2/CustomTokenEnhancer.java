package com.oauth.rest.security.oauth2;

import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Component;
import com.oauth.rest.model.UserEntity;


import java.util.HashMap;
import java.util.Map;

@Component
public class CustomTokenEnhancer implements TokenEnhancer {

    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {

        Object principal = authentication.getPrincipal();

        Map<String, Object> additionalInfo = new HashMap<>();

        if (principal instanceof UserEntity) {
            UserEntity usuario = (UserEntity) principal;
            additionalInfo.put("app", usuario.getApplication());
        }

        ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(additionalInfo);

        return accessToken;
    }
}

