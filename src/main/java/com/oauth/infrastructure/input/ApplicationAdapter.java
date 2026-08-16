package com.oauth.infrastructure.input;

import java.util.Optional;

import org.springframework.stereotype.Service;

import com.oauth.application.in.ApplicationUseCase;
import com.oauth.domain.ApplicationDomain;

/**
 * Adaptador de entrada que implementa el puerto de servicio de aplicaciones
 */
@Service
public class ApplicationAdapter implements ApplicationUseCase {

    private final ApplicationUseCase applicationUseCase;

    public ApplicationAdapter(ApplicationUseCase applicationUseCase) {
        this.applicationUseCase = applicationUseCase;
    }

    @Override
    public Optional<ApplicationDomain> findById(Long id) {
        return applicationUseCase.findById(id);
    }

    @Override
    public Optional<ApplicationDomain> findByClientId(String clientId) {
        return applicationUseCase.findByClientId(clientId);
    }

    @Override
    public Optional<ApplicationDomain> findByName(String name) {
        return applicationUseCase.findByName(name);
    }

    @Override
    public ApplicationDomain save(ApplicationDomain application) {
        return applicationUseCase.save(application);
    }

    @Override
    public void deleteById(Long id) {
        applicationUseCase.deleteById(id);
    }

    @Override
    public void delete(ApplicationDomain application) {
        applicationUseCase.delete(application);
    }
}
