package com.oauth.infrastructure.output.database.persistence;

import java.util.List;
import java.util.Optional;

import org.springframework.stereotype.Repository;

import com.oauth.application.in.user.UserApplicationUseCase;
import com.oauth.domain.UserApplicationDomain;

/**
 * Adaptador de salida que implementa el puerto de repositorio de
 * usuario-aplicación
 */
@Repository
public class UserApplicationRepositoryAdapter {

    private final UserApplicationUseCase usuarioAplicacionUseCase;

    public UserApplicationRepositoryAdapter(UserApplicationUseCase usuarioAplicacionUseCase) {
        this.usuarioAplicacionUseCase = usuarioAplicacionUseCase;
    }

    public Optional<UserApplicationDomain> findById(Long id) {
        return usuarioAplicacionUseCase.findById(id);
    }

    public List<UserApplicationDomain> findByUsuarioId(Long usuarioId) {
        return usuarioAplicacionUseCase.findByUsuarioId(usuarioId);
    }

    public List<UserApplicationDomain> findByApplicationId(Long applicationId) {
        return usuarioAplicacionUseCase.findByApplicationId(applicationId);
    }

    public Optional<UserApplicationDomain> findByUsuarioIdAndApplicationId(Long usuarioId, Long applicationId) {
        return usuarioAplicacionUseCase.findByUsuarioIdAndApplicationId(usuarioId, applicationId);
    }

    public UserApplicationDomain save(UserApplicationDomain userApplication) {
        return usuarioAplicacionUseCase.save(userApplication);
    }

    public void deleteById(Long id) {
        usuarioAplicacionUseCase.deleteById(id);
    }

    public void delete(UserApplicationDomain userApplication) {
        usuarioAplicacionUseCase.delete(userApplication);
    }
}
