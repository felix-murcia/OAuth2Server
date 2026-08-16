package com.oauth.application.service;

import java.util.Optional;

import org.springframework.stereotype.Service;

import com.oauth.application.in.RoleUseCase;
import com.oauth.application.out.persistence.RoleRepositoryPort;
import com.oauth.domain.RoleDomain;

@Service
public class RoleService implements RoleUseCase {

    private final RoleRepositoryPort roleRepositoryPort;

    public RoleService(RoleRepositoryPort roleRepositoryPort) {
        this.roleRepositoryPort = roleRepositoryPort;
    }

    @Override
    public Optional<RoleDomain> findByName(String name) {
        return roleRepositoryPort.findByName(name);
    }

    @Override
    public Optional<RoleDomain> findById(Long id) {
        return roleRepositoryPort.findById(id);
    }

    @Override
    public RoleDomain save(RoleDomain role) {
        return roleRepositoryPort.save(role);
    }

    @Override
    public void deleteById(Long id) {
        roleRepositoryPort.deleteById(id);
    }

    @Override
    public void delete(RoleDomain role) {
        roleRepositoryPort.delete(role);
    }

    @Override
    public RoleDomain findOrCreateRole(String name, String description) {
        return findByName(name).orElseGet(() -> {
            RoleDomain role = new RoleDomain(null, name, description, null, null);
            return save(role);
        });
    }
}
