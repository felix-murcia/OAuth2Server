package com.oauth.infrastructure.output.database.persistence;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.oauth.infrastructure.output.database.UsuarioAplicacionJpaEntity;

public interface UsuarioAplicacionRepository extends JpaRepository<UsuarioAplicacionJpaEntity, Long> {

    List<UsuarioAplicacionJpaEntity> findByUsuarioId(Long usuarioId);

    List<UsuarioAplicacionJpaEntity> findByApplicationId(Long applicationId);

    Optional<UsuarioAplicacionJpaEntity> findByUsuarioIdAndApplicationId(Long usuarioId, Long applicationId);

}
