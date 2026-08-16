package com.oauth.infrastructure.input.rest.mapper;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;

import org.springframework.stereotype.Component;

import com.oauth.domain.UserDomain;
import com.oauth.infrastructure.input.rest.dto.CreateUserDto;
import com.oauth.infrastructure.input.rest.dto.GetUserDto;

@Component
public class UserDtoMapper {

    public GetUserDto toGetUserDto(UserDomain user) {
        return new GetUserDto(
                user.id(),
                user.username(),
                user.fullName(),
                user.email(),
                Set.of(user.role()));
    }

    public UserDomain toUserDomain(CreateUserDto createUserDto) {
        return new UserDomain(
                null,
                createUserDto.getUsername(),
                Optional.ofNullable(createUserDto.getPassword()).orElse(createUserDto.getPassword2()),
                createUserDto.getEmail(),
                createUserDto.getFullName(),
                "ROLE_USER",
                true,
                true,
                true,
                true,
                Instant.now().toString(),
                Instant.now().toString());
    }

    // toUserDomain(GetUserDto) is not valid since UserDomain does not allow null
    // passwords.

}