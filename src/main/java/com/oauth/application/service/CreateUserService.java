package com.oauth.application.service;

import org.springframework.stereotype.Service;

import com.oauth.application.in.user.CreateUserUseCase;
import com.oauth.application.out.persistence.CreateUserRepositoryPort;
import com.oauth.domain.UserDomain;

@Service
public class CreateUserService implements CreateUserUseCase {

    private final CreateUserRepositoryPort createUserRepositoryPort;

    public CreateUserService(CreateUserRepositoryPort createUserRepositoryPort) {
        this.createUserRepositoryPort = createUserRepositoryPort;
    }

    @Override
    public UserDomain execute(UserDomain user) {
        return createUserRepositoryPort.save(user);
    }
}