package com.oauth.infrastructure.service

import com.oauth.domain.ApplicationDomain
import com.oauth.domain.UserDomain
import com.oauth.domain.UserApplicationDomain
import com.oauth.application.in.GetUserUseCase
import com.oauth.application.in.ApplicationUseCase
import com.oauth.application.in.UserApplicationUseCase
import com.oauth.infrastructure.security.CustomUserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import spock.lang.Specification
import java.time.Instant

class CustomUserDetailsServiceSpec extends Specification {

    GetUserUseCase getUserUseCase
    ApplicationUseCase applicationUseCase
    UserApplicationUseCase userApplicationUseCase
    CustomUserDetailsService customUserDetailsService

    def setup() {
        getUserUseCase = Mock(GetUserUseCase)
        applicationUseCase = Mock(ApplicationUseCase)
        userApplicationUseCase = Mock(UserApplicationUseCase)
        customUserDetailsService = new CustomUserDetailsService(
            getUserUseCase, 
            applicationUseCase, 
            userApplicationUseCase
        )
    }

    def "loadUserByUsername returns user when user exists"() {
        given:
        String username = "admin"
        UserDomain user = new UserDomain(1L, username, "hashedPassword", "admin@oauth.net", "Admin User", Set.of("ROLE_ADMIN"), true, true, true, true, Instant.now().toString(), Instant.now().toString())

        when:
        def result = customUserDetailsService.loadUserByUsername(username)

        then:
        1 * getUserUseCase.findByUsername(username) >> Optional.of(user)
        result.getUsername() == username
    }

    def "loadUserByUsername throws exception when user does not exist"() {
        given:
        String username = "nonexistent"

        when:
        customUserDetailsService.loadUserByUsername(username)

        then:
        1 * getUserUseCase.findByUsername(username) >> Optional.empty()
        thrown(UsernameNotFoundException)
    }

    def "loadUserByUsernameAndApplication returns user when user exists for app"() {
        given:
        String username = "admin"
        String appClientId = "cine-platform"
        UserDomain user = new UserDomain(1L, username, "hashedPassword", "admin@oauth.net", "Admin User", Set.of("ROLE_ADMIN"), true, true, true, true, Instant.now().toString(), Instant.now().toString())
        
        ApplicationDomain app = new ApplicationDomain(1L, appClientId, "secret", "Cine Platform", "Desc", "url", "client_credentials", "read", "3600", "7200", true, Instant.now().toString(), Instant.now().toString())

        when:
        def result = customUserDetailsService.loadUserByUsernameAndApplication(username, appClientId)

        then:
        1 * getUserUseCase.findByUsername(username) >> Optional.of(user)
        1 * applicationUseCase.findByClientId(appClientId) >> Optional.of(app)
        1 * userApplicationUseCase.findByUsuarioIdAndApplicationId(1L, 1L) >> Optional.of(new UserApplicationDomain(1L, user, app, java.time.LocalDateTime.now()))
        result.getUsername() == username
    }

    def "loadUserByUsernameAndApplication throws exception when user not registered for app"() {
        given:
        String username = "admin"
        String appClientId = "cine-platform"
        UserDomain user = new UserDomain(1L, username, "hashedPassword", "admin@oauth.net", "Admin User", Set.of("ROLE_ADMIN"), true, true, true, true, Instant.now().toString(), Instant.now().toString())
        
        ApplicationDomain app = new ApplicationDomain(1L, appClientId, "secret", "Cine Platform", "Desc", "url", "client_credentials", "read", "3600", "7200", true, Instant.now().toString(), Instant.now().toString())

        when:
        customUserDetailsService.loadUserByUsernameAndApplication(username, appClientId)

        then:
        1 * getUserUseCase.findByUsername(username) >> Optional.of(user)
        1 * applicationUseCase.findByClientId(appClientId) >> Optional.of(app)
        1 * userApplicationUseCase.findByUsuarioIdAndApplicationId(1L, 1L) >> Optional.empty()
        thrown(UsernameNotFoundException)
    }

    def "loadUserByUsernameAndApplication throws exception when user does not exist"() {
        given:
        String username = "nonexistent"
        String appClientId = "cine-platform"

        when:
        customUserDetailsService.loadUserByUsernameAndApplication(username, appClientId)

        then:
        1 * getUserUseCase.findByUsername(username) >> Optional.empty()
        thrown(UsernameNotFoundException)
    }

    def "isUserRegisteredInApplication returns true when user is registered"() {
        given:
        String username = "admin"
        String appClientId = "cine-platform"
        UserDomain user = new UserDomain(1L, username, "hashedPassword", "admin@oauth.net", "Admin User", Set.of("ROLE_ADMIN"), true, true, true, true, Instant.now().toString(), Instant.now().toString())
        
        ApplicationDomain app = new ApplicationDomain(1L, appClientId, "secret", "Cine Platform", "Desc", "url", "client_credentials", "read", "3600", "7200", true, Instant.now().toString(), Instant.now().toString())

        when:
        def result = customUserDetailsService.isUserRegisteredInApplication(username, appClientId)

        then:
        1 * getUserUseCase.findByUsername(username) >> Optional.of(user)
        1 * applicationUseCase.findByClientId(appClientId) >> Optional.of(app)
        1 * userApplicationUseCase.findByUsuarioIdAndApplicationId(1L, 1L) >> Optional.of(new UserApplicationDomain(1L, user, app, java.time.LocalDateTime.now()))
        result == true
    }

    def "isUserRegisteredInApplication returns false when user is not registered"() {
        given:
        String username = "admin"
        String appClientId = "cine-platform"
        UserDomain user = new UserDomain(1L, username, "hashedPassword", "admin@oauth.net", "Admin User", Set.of("ROLE_ADMIN"), true, true, true, true, Instant.now().toString(), Instant.now().toString())
        
        ApplicationDomain app = new ApplicationDomain(1L, appClientId, "secret", "Cine Platform", "Desc", "url", "client_credentials", "read", "3600", "7200", true, Instant.now().toString(), Instant.now().toString())


        when:
        def result = customUserDetailsService.isUserRegisteredInApplication(username, appClientId)

        then:
        1 * getUserUseCase.findByUsername(username) >> Optional.of(user)
        1 * applicationUseCase.findByClientId(appClientId) >> Optional.of(app)
        1 * userApplicationUseCase.findByUsuarioIdAndApplicationId(1L, 1L) >> Optional.empty()
        result == false
    }

    def "isUserRegisteredInApplication returns false when user does not exist"() {
        given:
        String username = "nonexistent"
        String appClientId = "cine-platform"

        when:
        def result = customUserDetailsService.isUserRegisteredInApplication(username, appClientId)

        then:
        1 * getUserUseCase.findByUsername(username) >> Optional.empty()
        result == false
    }
}
