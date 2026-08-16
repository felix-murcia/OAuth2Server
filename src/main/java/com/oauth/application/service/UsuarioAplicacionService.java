package com.oauth.application.service;

import java.util.List;
import java.util.Optional;

import com.oauth.application.in.UserApplicationUseCase;
import com.oauth.application.out.persistence.UserApplicationRepositoryPort;
import com.oauth.domain.UserApplicationDomain;

@org.springframework.stereotype.Service
public class UsuarioAplicacionService implements UserApplicationUseCase {

    private final UserApplicationRepositoryPort userApplicationRepositoryPort;

    public UsuarioAplicacionService(UserApplicationRepositoryPort userApplicationRepositoryPort) {
        this.userApplicationRepositoryPort = userApplicationRepositoryPort;
    }

    @Override
    public Optional<UserApplicationDomain> findByUsuarioIdAndApplicationId(Long usuarioId, Long applicationId) {
        return userApplicationRepositoryPort.findByUsuarioIdAndApplicationId(usuarioId, applicationId);
    }

    @Override
    public UserApplicationDomain save(UserApplicationDomain userApplication) {
        return userApplicationRepositoryPort.save(userApplication);
    }

    @Override
    public List<UserApplicationDomain> findByUsuarioId(Long usuarioId) {
        return userApplicationRepositoryPort.findByUsuarioId(usuarioId);
    }

    @Override
    public List<UserApplicationDomain> findByApplicationId(Long applicationId) {
        return userApplicationRepositoryPort.findByApplicationId(applicationId);
    }

    @Override
    public Optional<UserApplicationDomain> findById(Long id) {
        return userApplicationRepositoryPort.findById(id);
    }

    @Override
    public void deleteById(Long id) {
        userApplicationRepositoryPort.deleteById(id);
    }

    @Override
    public void delete(UserApplicationDomain userApplication) {
        userApplicationRepositoryPort.delete(userApplication);
    }
}
