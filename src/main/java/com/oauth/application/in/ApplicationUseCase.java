package com.oauth.application.in;

import java.util.Optional;

import com.oauth.domain.ApplicationDomain;

/**
 * Puerto de entrada para servicios de Aplicación
 * Define las operaciones de negocio relacionadas con aplicaciones OAuth
 */
public interface ApplicationUseCase {

    /**
     * Busca una aplicación por su ID
     */
    Optional<ApplicationDomain> findById(Long id);

    /**
     * Busca una aplicación por su clientId
     */
    Optional<ApplicationDomain> findByClientId(String clientId);

    /**
     * Busca una aplicación por su nombre
     */
    Optional<ApplicationDomain> findByName(String name);

    /**
     * Guarda una aplicación
     */
    ApplicationDomain save(ApplicationDomain application);

    /**
     * Elimina una aplicación por su ID
     */
    void deleteById(Long id);

    /**
     * Elimina una aplicación
     */
    void delete(ApplicationDomain application);
}
