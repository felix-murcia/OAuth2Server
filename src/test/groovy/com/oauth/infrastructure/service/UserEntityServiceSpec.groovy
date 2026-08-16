package com.oauth.infrastructure.service

import com.oauth.domain.UserDomain
import com.oauth.application.out.persistence.UserRepositoryPort
import com.oauth.application.service.UserEntityService
import spock.lang.Specification
import java.time.Instant

class UserEntityServiceSpec extends Specification {

    UserRepositoryPort userRepositoryPort
    UserEntityService userEntityService

    def setup() {
        userRepositoryPort = Mock(UserRepositoryPort)
        userEntityService = new UserEntityService(userRepositoryPort)
    }

    def "findByUsername returns user when user exists"() {
        given:
        String username = "admin"
        UserDomain user = new UserDomain(1L, username, "hashedPassword", "admin@oauth.net", "Admin User", "ROLE_ADMIN", true, true, true, true, Instant.now().toString(), Instant.now().toString())

        when:
        Optional<UserDomain> result = userEntityService.findByUsername(username)

        then:
        1 * userRepositoryPort.findByUsername(username) >> Optional.of(user)
        result.isPresent()
        result.get().username() == username
    }

    def "findByUsername returns empty when user does not exist"() {
        given:
        String username = "nonexistent"

        when:
        Optional<UserDomain> result = userEntityService.findByUsername(username)

        then:
        1 * userRepositoryPort.findByUsername(username) >> Optional.empty()
        !result.isPresent()
    }

    def "findByEmail returns user when email exists"() {
        given:
        String email = "admin@oauth.net"
        UserDomain user = new UserDomain(1L, "admin", "hashedPassword", email, "Admin User", "ROLE_ADMIN", true, true, true, true, Instant.now().toString(), Instant.now().toString())

        when:
        Optional<UserDomain> result = userEntityService.findByEmail(email)

        then:
        1 * userRepositoryPort.findByEmail(email) >> Optional.of(user)
        result.isPresent()
        result.get().email() == email
    }

    def "findByEmail returns empty when email does not exist"() {
        given:
        String email = "nonexistent@example.com"

        when:
        Optional<UserDomain> result = userEntityService.findByEmail(email)

        then:
        1 * userRepositoryPort.findByEmail(email) >> Optional.empty()
        !result.isPresent()
    }
}
