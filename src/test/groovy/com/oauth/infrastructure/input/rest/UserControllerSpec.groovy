package com.oauth.infrastructure.input.rest

import com.oauth.infrastructure.input.rest.dto.CreateUserDto
import com.oauth.infrastructure.input.rest.dto.GetUserDto
import com.oauth.infrastructure.input.rest.mapper.UserDtoMapper
import com.oauth.domain.UserDomain
import com.oauth.application.in.CreateUserUseCase
import com.oauth.application.in.GetUserUseCase
import spock.lang.Specification
import java.time.Instant

class UserControllerSpec extends Specification {

    CreateUserUseCase createUserUseCase
    GetUserUseCase getUserUseCase
    UserDtoMapper userDtoMapper
    UserController userController

    def setup() {
        createUserUseCase = Mock(CreateUserUseCase)
        getUserUseCase = Mock(GetUserUseCase)
        userDtoMapper = new UserDtoMapper()
        userController = new UserController(createUserUseCase, getUserUseCase, userDtoMapper)
    }

    def 'nuevoUsuario returns GetUserDto on success'() {
        given:
        CreateUserDto dto = new CreateUserDto()
        dto.setUsername('newuser')
        dto.setPassword('ValidPass123')
        dto.setPassword2('ValidPass123')
        dto.setFullName('New User')
        dto.setEmail('newuser@example.com')

        UserDomain user = new UserDomain(1L, 'newuser', 'hashedPassword', 'newuser@example.com', 'New User', Set.of('ROLE_USER'), true, true, true, true, Instant.now().toString(), Instant.now().toString())

        when:
        GetUserDto result = userController.nuevoUsuario(dto)

        then:
        1 * createUserUseCase.execute(_) >> user
        result != null
        result.username() == 'newuser'
        result.id() == 1L
        result.roles().contains('ROLE_USER')
    }

    def 'me returns GetUserDto from authenticated user dto'() {
        given:
        org.springframework.security.core.userdetails.UserDetails authenticatedUser = Mock(org.springframework.security.core.userdetails.UserDetails)
        authenticatedUser.getUsername() >> 'admin'
        
        UserDomain user = new UserDomain(1L, 'admin', 'hashedPassword', 'admin@example.com', 'Admin User', Set.of('ROLE_ADMIN'), true, true, true, true, Instant.now().toString(), Instant.now().toString())

        when:
        GetUserDto result = userController.me(authenticatedUser)

        then:
        1 * getUserUseCase.findByUsername('admin') >> Optional.of(user)
        result != null
        result.username() == 'admin'
        result.id() == 1L
        result.roles().contains('ROLE_ADMIN')
    }

    def 'me throws exception when user does not exist'() {
        given:
        org.springframework.security.core.userdetails.UserDetails authenticatedUser = Mock(org.springframework.security.core.userdetails.UserDetails)
        authenticatedUser.getUsername() >> 'nobody'
        
        when:
        userController.me(authenticatedUser)

        then:
        1 * getUserUseCase.findByUsername('nobody') >> Optional.empty()
        thrown(NoSuchElementException)
    }
}
