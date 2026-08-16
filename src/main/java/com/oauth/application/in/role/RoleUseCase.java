package com.oauth.application.in.role;

import java.util.Optional;

import com.oauth.domain.RoleDomain;

/**
 * Puerto de entrada para servicios de Rol
 * Define las operaciones de negocio relacionadas con roles
 */
public interface RoleUseCase {

    /**
     * Busca un rol por su nombre
     */
    Optional<RoleDomain> findByName(String name);

    /**
     * Busca un rol por su ID
     */
    Optional<RoleDomain> findById(Long id);

    /**
     * Guarda un rol
     */
    RoleDomain save(RoleDomain role);

    /**
     * Busca un rol por nombre o lo crea si no existe
     */
    RoleDomain findOrCreateRole(String name, String description);

    /**
     * Elimina un rol por su ID
     */
    void deleteById(Long id);

    /**
     * Elimina un rol
     */
    void delete(RoleDomain role);
}
