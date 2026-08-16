package com.oauth.application.out.persistence;

import com.oauth.domain.UserDomain;

public interface CreateUserRepositoryPort {
    UserDomain save(UserDomain user);
}
