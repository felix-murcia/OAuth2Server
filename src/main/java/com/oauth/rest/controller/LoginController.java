package com.oauth.rest.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import jakarta.annotation.PostConstruct;

import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.slf4j.Logger;

@Controller
public class LoginController {

    private static final Logger log = LoggerFactory.getLogger(LoginController.class);

    @Value("${app.contact.email:admin@localhost}")
    private String contactEmail;

        public LoginController() {
        log.info("🔴🔴🔴 LoginController INSTANCIADO 🔴🔴🔴");
    }

    @PostConstruct
    public void init() {
        log.info("🔴🔴🔴 LoginController inicializado (PostConstruct) 🔴🔴🔴");
    }
    
    @GetMapping("/login")
    public String login(
            @RequestParam(value = "error", required = false) String error,
            @RequestParam(value = "logout", required = false) String logout,
            @RequestParam(value = "registered", required = false) String registered,
            @RequestParam(value = "client_id", required = false) String clientId,
            Model model) {
        log.info("🔴 LoginController.login() llamado en entorno: {}", 
            System.getProperty("spring.profiles.active"));
        log.info("🔴 Parámetros recibidos - error: {}, logout: {}, clientId: {}", 
            error, logout, clientId);
        if (error != null) {
            model.addAttribute("error", "Usuario o contraseña incorrectos");
        }

        if (logout != null) {
            model.addAttribute("logout", "Sesión cerrada correctamente");
        }

        if (registered != null) {
            model.addAttribute("registered", "Usuario registrado correctamente");
        }

        // Pasar client_id al modelo (puede ser nulo si no viene en la URL)
        model.addAttribute("clientId", clientId);

        return "login";
    }

    /**
     * Página mostrada cuando el usuario intenta acceder directamente al login
     * sin un redirect_uri válido (flujo OAuth2).
     */
    @GetMapping("/invalid-application")
    public String invalidApplication(Model model) {
        model.addAttribute("contactEmail", contactEmail);
        return "invalid-application";
    }
}
