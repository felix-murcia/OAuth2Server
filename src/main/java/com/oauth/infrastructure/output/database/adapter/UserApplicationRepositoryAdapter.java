package com.oauth.infrastructure.output.database.adapter;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.stereotype.Repository;

import com.oauth.application.out.persistence.UserApplicationRepositoryPort;
import com.oauth.domain.ApplicationDomain;
import com.oauth.domain.UserApplicationDomain;
import com.oauth.domain.UserDomain;
import com.oauth.infrastructure.output.database.ApplicationJpaEntity;
import com.oauth.infrastructure.output.database.RoleJpaEntity;
import com.oauth.infrastructure.output.database.UserJpaEntity;
import com.oauth.infrastructure.output.database.UsuarioAplicacionJpaEntity;
import com.oauth.infrastructure.output.database.persistence.UsuarioAplicacionRepository;

@Repository
public class UserApplicationRepositoryAdapter implements UserApplicationRepositoryPort {

    private final UsuarioAplicacionRepository usuarioAplicacionRepository;

    public UserApplicationRepositoryAdapter(UsuarioAplicacionRepository usuarioAplicacionRepository) {
        this.usuarioAplicacionRepository = usuarioAplicacionRepository;
    }

    @Override
    public Optional<UserApplicationDomain> findById(Long id) {
        return usuarioAplicacionRepository.findById(id).map(this::toDomain);
    }

    @Override
    public List<UserApplicationDomain> findByUsuarioId(Long usuarioId) {
        return usuarioAplicacionRepository.findByUsuarioId(usuarioId).stream()
                .map(this::toDomain).collect(Collectors.toList());
    }

    @Override
    public List<UserApplicationDomain> findByApplicationId(Long applicationId) {
        return usuarioAplicacionRepository.findByApplicationId(applicationId).stream()
                .map(this::toDomain).collect(Collectors.toList());
    }

    @Override
    public Optional<UserApplicationDomain> findByUsuarioIdAndApplicationId(Long usuarioId, Long applicationId) {
        return usuarioAplicacionRepository.findByUsuarioIdAndApplicationId(usuarioId, applicationId)
                .map(this::toDomain);
    }

    @Override
    public UserApplicationDomain save(UserApplicationDomain userApplication) {
        UsuarioAplicacionJpaEntity entity = toEntity(userApplication);
        return toDomain(usuarioAplicacionRepository.save(entity));
    }

    @Override
    public void deleteById(Long id) {
        usuarioAplicacionRepository.deleteById(id);
    }

    @Override
    public void delete(UserApplicationDomain userApplication) {
        if (userApplication.id() != null) {
            usuarioAplicacionRepository.deleteById(userApplication.id());
        }
    }

    private UserApplicationDomain toDomain(UsuarioAplicacionJpaEntity entity) {
        return new UserApplicationDomain(
                entity.getId(),
                mapUser(entity.getUsuario()),
                mapApplication(entity.getApplication()),
                entity.getRegisteredAt());
    }

    private UsuarioAplicacionJpaEntity toEntity(UserApplicationDomain domain) {
        UsuarioAplicacionJpaEntity entity = new UsuarioAplicacionJpaEntity();
        if (domain.id() != null) {
            entity.setId(domain.id());
        }

        UserJpaEntity userEntity = new UserJpaEntity();
        userEntity.setId(domain.usuario().id());

        ApplicationJpaEntity appEntity = new ApplicationJpaEntity();
        appEntity.setId(domain.application().id());

        entity.setUsuario(userEntity);
        entity.setApplication(appEntity);
        return entity;
    }

    private UserDomain mapUser(UserJpaEntity entity) {
        String roleStr = entity.getRoles().stream().map(RoleJpaEntity::getName).findFirst().orElse("ROLE_USER");
        return new UserDomain(
                entity.getId(),
                entity.getUsername(),
                entity.getPassword(),
                entity.getEmail(),
                entity.getFullName() != null ? entity.getFullName() : "",
                roleStr,
                entity.getEnabled() != null ? entity.getEnabled() : true,
                true, true, true,
                entity.getCreatedAt() != null ? entity.getCreatedAt().toString() : Instant.now().toString(),
                Instant.now().toString());
    }

    private ApplicationDomain mapApplication(ApplicationJpaEntity entity) {
        return new ApplicationDomain(
                entity.getId(),
                entity.getClientId(),
                entity.getClientSecret(),
                entity.getName(),
                entity.getDescription(),
                entity.getRedirectUri() != null ? entity.getRedirectUri() : "",
                "authorization_code", "read", "3600", "86400", true,
                entity.getCreatedAt() != null ? entity.getCreatedAt().toString() : Instant.now().toString(),
                Instant.now().toString());
    }
}
