package com.oauth.infrastructure.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.oauth.application.in.GetUserUseCase;
import com.oauth.application.in.RoleUseCase;
import com.oauth.application.out.persistence.RoleRepositoryPort;
import com.oauth.application.out.persistence.UserRepositoryPort;
import com.oauth.application.service.RoleService;
import com.oauth.application.service.UserService;

@Configuration
public class UseCaseConfig {

    @Bean
    GetUserUseCase getUserUseCase(UserRepositoryPort userRepositoryPort) {
        return new UserService(userRepositoryPort);
    }

    @Bean
    RoleUseCase roleUseCase(RoleRepositoryPort roleRepositoryPort) {
        return new RoleService(roleRepositoryPort);
    }
}
