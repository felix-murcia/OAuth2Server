package com.oauth.infrastructure.output.database.persistence;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.oauth.infrastructure.output.database.RoleJpaEntity;

public interface RoleRepository extends JpaRepository<RoleJpaEntity, Long> {

    Optional<RoleJpaEntity> findByName(String name);

}
