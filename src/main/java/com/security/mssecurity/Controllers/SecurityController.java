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
        User created = theSecurityService.register(newUser);
        if (created == null) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(Map.of("error", "Email already registered"));
        }
        created.setPassword(null); // no devolver el hash
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
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
