package com.oauth.application.usecase.user

import com.oauth.domain.UserDomain
import com.oauth.application.out.persistence.CreateUserRepositoryPort
import com.oauth.application.service.CreateUserService
import spock.lang.Specification
import java.time.Instant

class CreateUserUseCaseSpec extends Specification {

    CreateUserRepositoryPort createUserRepositoryPort
    CreateUserService createUserService

    def setup() {
        createUserRepositoryPort = Mock(CreateUserRepositoryPort)
        createUserService = new CreateUserService(createUserRepositoryPort)
    }

    def 'execute creates user and returns UserDomain'() {
        given:
        UserDomain user = new UserDomain(null, "testuser", "Password123", "test@example.com", "Test User", Set.of("ROLE_USER"), true, true, true, true, Instant.now().toString(), Instant.now().toString())
        UserDomain savedUser = new UserDomain(1L, "testuser", "Password123", "test@example.com", "Test User", Set.of("ROLE_USER"), true, true, true, true, Instant.now().toString(), Instant.now().toString())

        when:
        def result = createUserService.execute(user)

        then:
        1 * createUserRepositoryPort.save(user) >> savedUser
        result.id() == 1L
        result.username() == 'testuser'
    }

    def 'execute propagates exceptions from repository'() {
        given:
        UserDomain user = new UserDomain(null, "existinguser", "Password123", "test@example.com", "Test User", Set.of("ROLE_USER"), true, true, true, true, Instant.now().toString(), Instant.now().toString())

        when:
        createUserService.execute(user)

        then:
        1 * createUserRepositoryPort.save(user) >> { throw new RuntimeException('Duplicate') }
        def ex = thrown(RuntimeException)
        ex.message == 'Duplicate'
    }
}
