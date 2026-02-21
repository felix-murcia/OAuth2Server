package com.oauth.rest;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.core.env.Environment;

@SpringBootApplication
public class Application {

	public static void main(String[] args) {
		SpringApplication app = new SpringApplication(Application.class);

		Environment env = app.run(args).getEnvironment();

		// Verificar configuración (solo para depuración)
		System.out.println("✅ Perfiles activos: " + String.join(", ", env.getActiveProfiles()));
		System.out.println("✅ URL H2: " + env.getProperty("spring.datasource.url"));
		System.out.println("✅ Driver: " + env.getProperty("spring.datasource.driverClassName"));
		System.out.println("✅ Puerto: " + env.getProperty("server.port"));
	}
}