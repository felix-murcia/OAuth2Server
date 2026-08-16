package com.oauth.infrastructure.output.database.adapter;

import java.time.Instant;
import java.util.Optional;

import org.springframework.stereotype.Repository;

import com.oauth.application.out.persistence.RoleRepositoryPort;
import com.oauth.domain.RoleDomain;
import com.oauth.infrastructure.output.database.RoleJpaEntity;
import com.oauth.infrastructure.output.database.persistence.RoleRepository;

@Repository
public class RoleRepositoryAdapter implements RoleRepositoryPort {

    private final RoleRepository roleRepository;

    public RoleRepositoryAdapter(RoleRepository roleRepository) {
        this.roleRepository = roleRepository;
    }

    @Override
    public Optional<RoleDomain> findById(Long id) {
        return roleRepository.findById(id).map(this::toDomain);
    }

    @Override
    public Optional<RoleDomain> findByName(String name) {
        return roleRepository.findByName(name).map(this::toDomain);
    }

    @Override
    public RoleDomain save(RoleDomain role) {
        RoleJpaEntity entity = toEntity(role);
        return toDomain(roleRepository.save(entity));
    }

    @Override
    public void deleteById(Long id) {
        roleRepository.deleteById(id);
    }

    @Override
    public void delete(RoleDomain role) {
        if (role.id() != null) {
            roleRepository.deleteById(role.id());
        }
    }

    private RoleDomain toDomain(RoleJpaEntity entity) {
        return new RoleDomain(
                entity.getId(),
                entity.getName(),
                entity.getDescription() != null ? entity.getDescription() : "",
                Instant.now().toString(),
                Instant.now().toString());
    }

    private RoleJpaEntity toEntity(RoleDomain domain) {
        RoleJpaEntity entity = new RoleJpaEntity();
        entity.setId(domain.id());
        entity.setName(domain.name());
        entity.setDescription(domain.description());
        return entity;
    }
}
