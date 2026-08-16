package com.oauth.infrastructure.output.database.adapter;

import java.time.Instant;
import java.util.Optional;

import org.springframework.stereotype.Repository;

import com.oauth.application.out.persistence.ApplicationRepositoryPort;
import com.oauth.domain.ApplicationDomain;
import com.oauth.infrastructure.output.database.ApplicationJpaEntity;
import com.oauth.infrastructure.output.database.persistence.ApplicationRepository;

@Repository
public class ApplicationRepositoryAdapter implements ApplicationRepositoryPort {

    private final ApplicationRepository applicationRepository;

    public ApplicationRepositoryAdapter(ApplicationRepository applicationRepository) {
        this.applicationRepository = applicationRepository;
    }

    @Override
    public Optional<ApplicationDomain> findById(Long id) {
        return applicationRepository.findById(id).map(this::toDomain);
    }

    @Override
    public Optional<ApplicationDomain> findByClientId(String clientId) {
        return applicationRepository.findByClientId(clientId).map(this::toDomain);
    }

    @Override
    public Optional<ApplicationDomain> findByName(String name) {
        return applicationRepository.findByName(name).map(this::toDomain);
    }

    @Override
    public ApplicationDomain save(ApplicationDomain application) {
        ApplicationJpaEntity entity = toEntity(application);
        return toDomain(applicationRepository.save(entity));
    }

    @Override
    public void deleteById(Long id) {
        applicationRepository.deleteById(id);
    }

    @Override
    public void delete(ApplicationDomain application) {
        if (application.id() != null) {
            applicationRepository.deleteById(application.id());
        }
    }

    private ApplicationDomain toDomain(ApplicationJpaEntity entity) {
        return new ApplicationDomain(
                entity.getId(),
                entity.getClientId(),
                entity.getClientSecret(),
                entity.getName(),
                entity.getDescription(),
                entity.getRedirectUri() != null ? entity.getRedirectUri() : "",
                "authorization_code",
                "read.write",
                "3600",
                "86400",
                true,
                entity.getCreatedAt() != null ? entity.getCreatedAt().toString() : Instant.now().toString(),
                Instant.now().toString());
    }

    private ApplicationJpaEntity toEntity(ApplicationDomain domain) {
        ApplicationJpaEntity entity = new ApplicationJpaEntity();
        entity.setId(domain.id());
        entity.setClientId(domain.clientId());
        entity.setClientSecret(domain.clientSecret());
        entity.setName(domain.name());
        entity.setDescription(domain.description());
        entity.setRedirectUri(domain.redirectUri());
        return entity;
    }
}
