package com.oauth.application.out.persistence;

import java.util.Optional;

import com.oauth.domain.ApplicationDomain;

/**
 * Puerto de salida para operaciones de repositorio de aplicaciones
 */
public interface ApplicationRepositoryPort {

    Optional<ApplicationDomain> findById(Long id);

    Optional<ApplicationDomain> findByClientId(String clientId);

    Optional<ApplicationDomain> findByName(String name);

    ApplicationDomain save(ApplicationDomain application);

    void deleteById(Long id);

    void delete(ApplicationDomain application);
}
