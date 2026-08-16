package com.oauth.application.in.user;

import com.oauth.domain.UserDomain;

/**
 * Puerto de entrada para el caso de uso de creación de usuario
 * Define la interfaz que implementa el caso de uso
 */
public interface CreateUserUseCase {

    /**
     * Ejecuta el caso de uso para crear un nuevo usuario
     * 
     * @param username  nombre de usuario
     * @param email     correo electrónico
     * @param password  contraseña
     * @param password2 confirmación de contraseña
     * @param fullName  nombre completo
     * @return CompletableFuture con el usuario creado
     */
    UserDomain execute(UserDomain user);
}
