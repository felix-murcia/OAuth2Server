package com.oauth.infrastructure.output.database.persistence;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.oauth.infrastructure.output.database.UserJpaEntity;

public interface UserEntityRepository extends JpaRepository<UserJpaEntity, Long> {

	Optional<UserJpaEntity> findByUsername(String username);

	Optional<UserJpaEntity> findByEmail(String email);

}
