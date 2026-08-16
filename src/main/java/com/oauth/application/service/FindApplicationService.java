package com.oauth.application.service;

import java.util.Optional;

import com.oauth.application.in.ApplicationUseCase;
import com.oauth.application.out.persistence.ApplicationRepositoryPort;
import com.oauth.domain.ApplicationDomain;

@org.springframework.stereotype.Service
public class FindApplicationService implements ApplicationUseCase {

    private final ApplicationRepositoryPort applicationRepositoryPort;

    public FindApplicationService(ApplicationRepositoryPort applicationRepositoryPort) {
        this.applicationRepositoryPort = applicationRepositoryPort;
    }

    /**
     * Busca una aplicación por su ID
     */
    @Override
    public Optional<ApplicationDomain> findById(Long id) {
        return applicationRepositoryPort.findById(id);
    }

    /**
     * Busca una aplicación por su clientId
     */
    @Override
    public Optional<ApplicationDomain> findByClientId(String clientId) {
        return applicationRepositoryPort.findByClientId(clientId);
    }

    /**
     * Busca una aplicación por su nombre
     */
    @Override
    public Optional<ApplicationDomain> findByName(String name) {
        return applicationRepositoryPort.findByName(name);
    }

    @Override
    public ApplicationDomain save(ApplicationDomain application) {
        return applicationRepositoryPort.save(application);
    }

    @Override
    public void deleteById(Long id) {
        applicationRepositoryPort.deleteById(id);
    }

    @Override
    public void delete(ApplicationDomain application) {
        applicationRepositoryPort.delete(application);
    }
}
