package com.oauth.application.in.user;

import java.util.Optional;

import com.oauth.domain.UserDomain;

/**
 * Puerto de entrada para el caso de uso de obtención de usuario
 * Define la interfaz que implementa el caso de uso
 */
public interface GetUserUseCase {

    /**
     * Busca un usuario por su nombre de usuario
     */
    Optional<UserDomain> findByUsername(String username);

    /**
     * Busca un usuario por su ID
     */
    Optional<UserDomain> findById(Long id);

    /**
     * Busca un usuario por su correo electrónico
     */
    Optional<UserDomain> findByEmail(String email);

    UserDomain save(UserDomain user);

    void deleteById(Long id);

    void delete(UserDomain user);
}
