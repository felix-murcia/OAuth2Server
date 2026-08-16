package com.oauth.infrastructure.output.database.persistence;

import java.util.Optional;

import org.springframework.stereotype.Repository;

import com.oauth.domain.RoleDomain;
import com.oauth.application.in.role.RoleUseCase;

/**
 * Adaptador de salida que implementa el puerto de repositorio de roles
 */
@Repository
public class RoleRepositoryAdapter {

    private final RoleUseCase roleUseCase;

    public RoleRepositoryAdapter(RoleUseCase roleUseCase) {
        this.roleUseCase = roleUseCase;
    }

    public Optional<RoleDomain> findById(Long id) {
        return roleUseCase.findById(id);
    }

    public Optional<RoleDomain> findByName(String name) {
        return roleUseCase.findByName(name);
    }

    public RoleDomain save(RoleDomain role) {
        return roleUseCase.save(role);
    }

    public void deleteById(Long id) {
        roleUseCase.deleteById(id);
    }

    public void delete(RoleDomain role) {
        roleUseCase.delete(role);
    }
}
