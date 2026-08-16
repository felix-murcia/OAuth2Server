package com.oauth.infrastructure.output.database.persistence;

import java.util.Optional;

import org.springframework.stereotype.Repository;

import com.oauth.application.in.application.ApplicationUseCase;
import com.oauth.domain.ApplicationDomain;

/**
 * Adaptador de salida que implementa el puerto de repositorio de aplicaciones
 */
@Repository
public class ApplicationRepositoryAdapter {

    private final ApplicationUseCase applicationUseCase;

    public ApplicationRepositoryAdapter(ApplicationUseCase applicationUseCase) {
        this.applicationUseCase = applicationUseCase;
    }

    public Optional<ApplicationDomain> findById(Long id) {
        return applicationUseCase.findById(id);
    }

    public Optional<ApplicationDomain> findByClientId(String clientId) {
        return applicationUseCase.findByClientId(clientId);
    }

    public Optional<ApplicationDomain> findByName(String name) {
        return applicationUseCase.findByName(name);
    }

    public ApplicationDomain save(ApplicationDomain application) {
        return applicationUseCase.save(application);
    }

    public void deleteById(Long id) {
        applicationUseCase.deleteById(id);
    }

    public void delete(ApplicationDomain application) {
        applicationUseCase.delete(application);
    }
}
