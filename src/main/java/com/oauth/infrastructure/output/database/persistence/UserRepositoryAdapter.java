package com.oauth.infrastructure.output.database.persistence;

import java.util.Optional;

import org.springframework.stereotype.Repository;

import com.oauth.application.in.user.GetUserUseCase;
import com.oauth.domain.UserDomain;

/**
 * Adaptador de salida que implementa el puerto de repositorio de usuarios
 */
@Repository
public class UserRepositoryAdapter {

    private final GetUserUseCase getUserUseCase;

    public UserRepositoryAdapter(GetUserUseCase getUserUseCase) {
        this.getUserUseCase = getUserUseCase;
    }

    public Optional<UserDomain> findById(Long id) {
        return getUserUseCase.findById(id);
    }

    public Optional<UserDomain> findByUsername(String username) {
        return getUserUseCase.findByUsername(username);
    }

    public Optional<UserDomain> findByEmail(String email) {
        return getUserUseCase.findByEmail(email);
    }

    public UserDomain save(UserDomain user) {
        return getUserUseCase.save(user);
    }

    public void deleteById(Long id) {
        getUserUseCase.deleteById(id);
    }

    public void delete(UserDomain user) {
        getUserUseCase.delete(user);
    }
}
