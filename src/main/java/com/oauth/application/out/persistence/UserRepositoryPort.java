package com.oauth.application.out.persistence;

import java.util.Optional;

import com.oauth.domain.UserDomain;

/**
 * Puerto de salida para operaciones de repositorio de usuarios
 */
public interface UserRepositoryPort {

    Optional<UserDomain> findById(Long id);

    Optional<UserDomain> findByUsername(String username);

    Optional<UserDomain> findByEmail(String email);

    UserDomain save(UserDomain user);

    void deleteById(Long id);

    void delete(UserDomain user);
}
