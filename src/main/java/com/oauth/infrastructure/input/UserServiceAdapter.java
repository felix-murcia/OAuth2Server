package com.oauth.infrastructure.input;

import java.util.Optional;

import org.springframework.stereotype.Service;

import com.oauth.application.in.GetUserUseCase;
import com.oauth.domain.UserDomain;

/**
 * Adaptador de entrada que implementa el puerto de servicio de usuarios
 */
@Service
public class UserServiceAdapter {

    private final GetUserUseCase userUseCase;

    public UserServiceAdapter(GetUserUseCase userUseCase) {
        this.userUseCase = userUseCase;
    }

    public Optional<UserDomain> findByUsername(String username) {
        return userUseCase.findByUsername(username);
    }

    public Optional<UserDomain> findByEmail(String email) {
        return userUseCase.findByEmail(email);
    }

    public Optional<UserDomain> findById(Long id) {
        return userUseCase.findById(id);
    }

    public UserDomain save(UserDomain user) {
        return userUseCase.save(user);
    }
}
