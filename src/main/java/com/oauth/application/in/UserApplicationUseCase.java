package com.oauth.application.in;

import java.util.List;
import java.util.Optional;

import com.oauth.domain.UserApplicationDomain;

public interface UserApplicationUseCase {
    Optional<UserApplicationDomain> findByUsuarioIdAndApplicationId(Long usuarioId, Long applicationId);

    UserApplicationDomain save(UserApplicationDomain userApplication);

    List<UserApplicationDomain> findByUsuarioId(Long usuarioId);

    List<UserApplicationDomain> findByApplicationId(Long applicationId);

    Optional<UserApplicationDomain> findById(Long id);

    void deleteById(Long id);

    void delete(UserApplicationDomain userApplication);
}
