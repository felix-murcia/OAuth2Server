package com.oauth.rest.service

import com.oauth.rest.model.UserEntity
import com.oauth.rest.model.UserRole
import org.springframework.security.core.userdetails.UsernameNotFoundException
import spock.lang.Specification

class CustomUserDetailsServiceSpec extends Specification {

    UserEntityService userEntityService
    CustomUserDetailsService customUserDetailsService

    def setup() {
        userEntityService = Mock(UserEntityService)
        customUserDetailsService = new CustomUserDetailsService(userEntityService)
    }

    def "loadUserByUsername returns user when user exists"() {
        given:
        String username = "admin"
        UserEntity user = new UserEntity()
        user.setUsername(username)
        user.setPassword("hashedPassword")
        user.setRoles(Set.of(UserRole.ADMIN))

        when:
        def result = customUserDetailsService.loadUserByUsername(username)

        then:
        1 * userEntityService.findUserByUsername(username) >> Optional.of(user)
        result.getUsername() == username
    }

    def "loadUserByUsername throws exception when user does not exist"() {
        given:
        String username = "nonexistent"

        when:
        customUserDetailsService.loadUserByUsername(username)

        then:
        1 * userEntityService.findUserByUsername(username) >> Optional.empty()
        thrown(UsernameNotFoundException)
    }
}
