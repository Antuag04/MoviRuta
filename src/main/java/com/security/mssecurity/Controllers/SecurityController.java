package com.security.mssecurity.Controllers;

import com.security.mssecurity.Models.User;
import com.security.mssecurity.Services.SecurityService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@CrossOrigin
@RestController
@RequestMapping("/api/public/security")
public class SecurityController {

    @Autowired
    private SecurityService theSecurityService;

    @PostMapping("register")
    public ResponseEntity<?> register(@RequestBody User newUser) {
        try {
            User created = theSecurityService.register(newUser);
            created.setPassword(null); // no devolver el hash
            return ResponseEntity.status(HttpStatus.CREATED).body(created);
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("login")
    public ResponseEntity<?> login(@RequestBody User theUser) {
        String token = theSecurityService.login(theUser);
        if (token == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Credenciales inválidas"));
        }
        return ResponseEntity.ok(Map.of("token", token));
    }
}
