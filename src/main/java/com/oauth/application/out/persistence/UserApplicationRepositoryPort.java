package com.oauth.application.out.persistence;

import java.util.List;
import java.util.Optional;

import com.oauth.domain.UserApplicationDomain;

/**
 * Puerto de salida para operaciones de repositorio de usuario-aplicación
 */
public interface UserApplicationRepositoryPort {

    Optional<UserApplicationDomain> findById(Long id);

    List<UserApplicationDomain> findByUsuarioId(Long usuarioId);

    List<UserApplicationDomain> findByApplicationId(Long applicationId);

    Optional<UserApplicationDomain> findByUsuarioIdAndApplicationId(Long usuarioId, Long applicationId);

    UserApplicationDomain save(UserApplicationDomain userApplication);

    void deleteById(Long id);

    void delete(UserApplicationDomain userApplication);
}
