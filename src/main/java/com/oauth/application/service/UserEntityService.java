package com.oauth.application.service;

import java.util.Optional;

import com.oauth.application.in.user.GetUserUseCase;
import com.oauth.application.out.persistence.UserRepositoryPort;
import com.oauth.domain.UserDomain;

public class UserEntityService implements GetUserUseCase {

    private final UserRepositoryPort userRepositoryPort;

    public UserEntityService(UserRepositoryPort userRepositoryPort) {
        this.userRepositoryPort = userRepositoryPort;
    }

    @Override
    public Optional<UserDomain> findByUsername(String username) {
        return userRepositoryPort.findByUsername(username);
    }

    @Override
    public Optional<UserDomain> findById(Long id) {
        return userRepositoryPort.findById(id);
    }

    @Override
    public Optional<UserDomain> findByEmail(String email) {
        return userRepositoryPort.findByEmail(email);
    }

    @Override
    public UserDomain save(UserDomain user) {
        return userRepositoryPort.save(user);
    }

    @Override
    public void deleteById(Long id) {
        userRepositoryPort.deleteById(id);
    }

    @Override
    public void delete(UserDomain user) {
        userRepositoryPort.delete(user);
    }
}
