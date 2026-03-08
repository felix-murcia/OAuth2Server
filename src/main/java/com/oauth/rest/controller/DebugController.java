package com.oauth.rest.controller;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/debug")
public class DebugController {

    private final PasswordEncoder passwordEncoder;

    public DebugController(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/check-password")
    public String checkPassword(@RequestParam String username, 
                                 @RequestParam String rawPassword,
                                 @RequestParam String storedHash) {
        boolean matches = passwordEncoder.matches(rawPassword, storedHash);
        return String.format("Password '%s' %s with hash '%s'", 
            rawPassword, 
            matches ? "✅ COINCIDE" : "❌ NO COINCIDE", 
            storedHash);
    }

    @GetMapping("/encode")
    public String encode(@RequestParam String password) {
        return passwordEncoder.encode(password);
    }
}