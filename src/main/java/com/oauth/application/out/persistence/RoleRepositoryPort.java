package com.oauth.application.out.persistence;

import java.util.Optional;

import com.oauth.domain.RoleDomain;

/**
 * Puerto de salida para operaciones de repositorio de roles
 */
public interface RoleRepositoryPort {

    Optional<RoleDomain> findById(Long id);

    Optional<RoleDomain> findByName(String name);

    RoleDomain save(RoleDomain role);

    void deleteById(Long id);

    void delete(RoleDomain role);
}
