package com.oauth.infrastructure.output.database.adapter;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;

import org.springframework.stereotype.Repository;

import com.oauth.application.out.persistence.CreateUserRepositoryPort;
import com.oauth.application.out.persistence.UserRepositoryPort;
import com.oauth.domain.UserDomain;
import com.oauth.infrastructure.output.database.RoleJpaEntity;
import com.oauth.infrastructure.output.database.UserJpaEntity;
import com.oauth.infrastructure.output.database.persistence.RoleRepository;
import com.oauth.infrastructure.output.database.persistence.UserEntityRepository;

@Repository
public class UserRepositoryAdapter implements UserRepositoryPort, CreateUserRepositoryPort {

    private final UserEntityRepository userRepository;
    private final RoleRepository roleRepository;

    public UserRepositoryAdapter(UserEntityRepository userRepository, RoleRepository roleRepository) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
    }

    @Override
    public Optional<UserDomain> findById(Long id) {
        return userRepository.findById(id).map(this::toDomain);
    }

    @Override
    public Optional<UserDomain> findByUsername(String username) {
        return userRepository.findByUsername(username).map(this::toDomain);
    }

    @Override
    public Optional<UserDomain> findByEmail(String email) {
        return userRepository.findByEmail(email).map(this::toDomain);
    }

    @Override
    public UserDomain save(UserDomain user) {
        UserJpaEntity entity = toEntity(user);
        return toDomain(userRepository.save(entity));
    }

    @Override
    public void deleteById(Long id) {
        userRepository.deleteById(id);
    }

    @Override
    public void delete(UserDomain user) {
        if (user.id() != null) {
            userRepository.deleteById(user.id());
        }
    }

    private UserDomain toDomain(UserJpaEntity entity) {
        String roleStr = entity.getRoles().stream()
                .map(RoleJpaEntity::getName)
                .findFirst()
                .orElse("ROLE_USER");

        return new UserDomain(
                entity.getId(),
                entity.getUsername(),
                entity.getPassword(),
                entity.getEmail(),
                entity.getFullName() != null ? entity.getFullName() : "",
                roleStr,
                entity.getEnabled() != null ? entity.getEnabled() : true,
                true,
                true,
                true,
                entity.getCreatedAt() != null ? entity.getCreatedAt().toString() : Instant.now().toString(),
                Instant.now().toString());
    }

    private UserJpaEntity toEntity(UserDomain domain) {
        UserJpaEntity entity = new UserJpaEntity();
        if (domain.id() != null) {
            entity.setId(domain.id());
        }
        entity.setUsername(domain.username());
        entity.setPassword(domain.password());
        entity.setEmail(domain.email());
        entity.setFullName(domain.fullName());
        entity.setEnabled(domain.enabled());

        RoleJpaEntity roleOpt = roleRepository.findByName(domain.role())
                .orElseGet(() -> {
                    RoleJpaEntity r = new RoleJpaEntity();
                    r.setName(domain.role());
                    r.setDescription(domain.role());
                    return roleRepository.save(r);
                });
        entity.setRoles(Set.of(roleOpt));

        return entity;
    }
}
