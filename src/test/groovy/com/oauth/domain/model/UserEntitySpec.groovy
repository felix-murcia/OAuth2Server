package com.oauth.domain

import spock.lang.Specification
import java.time.Instant

class UserDomainSpec extends Specification {

    def 'UserDomain cannot be created with null values'() {
        when:
        new UserDomain(null, null, null, null, null, null, true, true, true, true, null, null)

        then:
        thrown(IllegalArgumentException)
    }

    def 'UserDomain can be created with valid values'() {
        when:
        def user = new UserDomain(1L, "testuser", "password123", "test@example.com", "Test User", Set.of("ROLE_USER"), true, true, true, true, Instant.now().toString(), Instant.now().toString())

        then:
        user.username() == "testuser"
        user.email() == "test@example.com"
        user.password() == "password123"
        user.roles().contains("ROLE_USER")
    }
}
