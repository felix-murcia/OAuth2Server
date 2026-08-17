package com.oauth.infrastructure.input.rest.mapper

import com.oauth.infrastructure.input.rest.dto.GetUserDto
import com.oauth.infrastructure.input.rest.dto.CreateUserDto
import com.oauth.domain.UserDomain
import spock.lang.Specification
import java.time.Instant

class UserDtoMapperSpec extends Specification {

    def 'toGetUserDto maps UserDomain to GetUserDto'() {
        given:
        UserDomain user = new UserDomain(1L, "testuser", "hashedPassword", "test@example.com", "Test User", Set.of("ROLE_USER"), true, true, true, true, Instant.now().toString(), Instant.now().toString())

        UserDtoMapper mapper = new UserDtoMapper()

        when:
        GetUserDto dto = mapper.toGetUserDto(user)

        then:
        dto.username() == 'testuser'
        dto.email() == 'test@example.com'
        dto.fullName() == 'Test User'
        dto.roles() != null
        dto.roles().contains('ROLE_USER')
    }

    def 'toUserDomain maps CreateUserDto to UserDomain'() {
        given:
        CreateUserDto dto = new CreateUserDto(
            username: 'admin',
            email: 'admin@example.com',
            password: 'password',
            password2: 'password',
            fullName: 'Admin User'
        )

        UserDtoMapper mapper = new UserDtoMapper()

        when:
        UserDomain user = mapper.toUserDomain(dto)

        then:
        user.username() == 'admin'
        user.password() == 'password'
        user.email() == 'admin@example.com'
        user.fullName() == 'Admin User'
        user.roles().contains('ROLE_USER')
    }

}
