package com.oauth.infrastructure.output.security;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import java.util.List;

import com.oauth.application.in.user.GetUserUseCase;
import com.oauth.application.in.application.ApplicationUseCase;
import com.oauth.application.in.user.UserApplicationUseCase;
import com.oauth.domain.UserDomain;

public class CustomUserDetailsService implements UserDetailsService {

        private final GetUserUseCase getUserUseCase;
        private final ApplicationUseCase applicationUseCase;
        private final UserApplicationUseCase userApplicationUseCase;

        public CustomUserDetailsService(GetUserUseCase getUserUseCase,
                        ApplicationUseCase applicationUseCase,
                        UserApplicationUseCase userApplicationUseCase) {
                this.getUserUseCase = getUserUseCase;
                this.applicationUseCase = applicationUseCase;
                this.userApplicationUseCase = userApplicationUseCase;
        }

        @Override
        public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
                UserDomain userDomain = getUserUseCase.findByUsername(username)
                                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado: " + username));
                return toUserDetails(userDomain);
        }

        public UserDetails loadUserByUsernameAndApplication(String username, String applicationClientId) {
                UserDomain userDomain = getUserUseCase.findByUsername(username)
                                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado: " + username));

                if (!applicationUseCase.findByClientId(applicationClientId)
                                .map(app -> userApplicationUseCase
                                                .findByUsuarioIdAndApplicationId(userDomain.id(), app.id())
                                                .isPresent())
                                .orElse(false)) {
                        throw new UsernameNotFoundException(
                                        "Usuario no encontrado: " + username + " para la app: " + applicationClientId);
                }

                return toUserDetails(userDomain);
        }

        public boolean isUserRegisteredInApplication(String username, String applicationClientId) {
                var userDomain = getUserUseCase.findByUsername(username)
                                .orElse(null);

                if (userDomain == null) {
                        return false;
                }

                return applicationUseCase.findByClientId(applicationClientId)
                                .map(app -> userApplicationUseCase
                                                .findByUsuarioIdAndApplicationId(userDomain.id(), app.id())
                                                .isPresent())
                                .orElse(false);
        }

        private UserDetails toUserDetails(UserDomain userDomain) {
                return new User(
                                userDomain.username(),
                                userDomain.password(),
                                userDomain.enabled(),
                                userDomain.accountNonExpired(),
                                userDomain.credentialsNonExpired(),
                                userDomain.accountNonLocked(),
                                List.of(new SimpleGrantedAuthority(userDomain.role())));
        }
}
