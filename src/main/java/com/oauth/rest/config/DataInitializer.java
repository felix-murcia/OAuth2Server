package com.oauth.rest.config;

import com.oauth.rest.model.UserEntity;
import com.oauth.rest.model.UserRole;
import com.oauth.rest.repository.UserEntityRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Set;

@Configuration
public class DataInitializer {

    @Value("${oauth2.default-user.username:admin}")
    private String defaultUsername;

    @Value("${oauth2.default-user.password:Admin1}")
    private String defaultPassword;

    @Bean
    public CommandLineRunner initUsers(UserEntityRepository userRepository, PasswordEncoder passwordEncoder) {
        return args -> {
            if (userRepository.count() == 0) {
                // Crear usuario admin desde propiedades
                UserEntity admin = new UserEntity();
                admin.setUsername(defaultUsername);
                admin.setPassword(passwordEncoder.encode(defaultPassword));
                admin.setFullName("Admin admin");
                admin.setEmail("admin@oauth.net");
                admin.setRoles(Set.of(UserRole.USER, UserRole.ADMIN));
                userRepository.save(admin);

                // Crear usuario normal
                UserEntity user = new UserEntity();
                user.setUsername("user1");
                user.setPassword(passwordEncoder.encode("User1"));
                user.setFullName("user 1");
                user.setEmail("usuario1@oauth.net");
                user.setRoles(Set.of(UserRole.USER));
                userRepository.save(user);

                System.out.println("Usuarios inicializados correctamente");
                System.out.println("Usuario admin: " + defaultUsername + " / " + defaultPassword);
            }
        };
    }
}
