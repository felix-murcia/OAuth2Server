package com.oauth.infrastructure.output.database.persistence;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.oauth.infrastructure.output.database.ApplicationJpaEntity;

public interface ApplicationRepository extends JpaRepository<ApplicationJpaEntity, Long> {

    Optional<ApplicationJpaEntity> findByClientId(String clientId);

    Optional<ApplicationJpaEntity> findByName(String name);

}
