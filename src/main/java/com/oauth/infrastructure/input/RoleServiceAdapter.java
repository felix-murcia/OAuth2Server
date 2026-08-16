package com.oauth.infrastructure.input;

import java.util.Optional;

import org.springframework.stereotype.Service;

import com.oauth.application.in.role.RoleUseCase;
import com.oauth.domain.RoleDomain;

@Service
public class RoleServiceAdapter {

    private final RoleUseCase roleUseCase;

    public RoleServiceAdapter(RoleUseCase roleUseCase) {
        this.roleUseCase = roleUseCase;
    }

    public Optional<RoleDomain> findByName(String name) {
        return roleUseCase.findByName(name);
    }

    public Optional<RoleDomain> findById(Long id) {
        return roleUseCase.findById(id);
    }

    public RoleDomain save(RoleDomain role) {
        return roleUseCase.save(role);
    }

    public RoleDomain findOrCreateRole(String name, String description) {
        return roleUseCase.findByName(name)
                .orElseGet(() -> {
                    RoleDomain role = new RoleDomain(null, name, description, null, null);
                    return roleUseCase.save(role);
                });
    }
}
