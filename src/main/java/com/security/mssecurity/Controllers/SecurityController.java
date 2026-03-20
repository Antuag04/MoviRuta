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

/**
 * Controlador REST que gestiona los endpoints de autenticación tradicional.
 * 
 * Este controlador expone endpoints públicos bajo /api/public/security para:
 * - POST /register: Registro de nuevos usuarios con email y contraseña
 * - POST /login: Inicio de sesión tradicional
 * 
 * Estos endpoints son públicos y no requieren autenticación previa.
 * 
 * @see SecurityService
 */
@CrossOrigin
@RestController
@RequestMapping("/api/public/security")
public class SecurityController {

    @Autowired
    private SecurityService theSecurityService;

    /**
     * Registra un nuevo usuario en el sistema.
     * 
     * El registro incluye validaciones de datos obligatorios y verificación
     * de email duplicado. Al completarse exitosamente, se asigna automáticamente
     * el rol "CIUDADANO" al nuevo usuario.
     * 
     * Campos requeridos en el body:
     * - name: Nombre completo del usuario
     * - email: Correo electrónico (debe ser único)
     * - password: Contraseña (será encriptada con BCrypt)
     * 
     * @param newUser Objeto User con los datos del nuevo usuario
     * @return ResponseEntity con el usuario creado (sin password) o mensaje de error
     */
    @PostMapping("register")
    public ResponseEntity<?> register(@RequestBody User newUser) {
        try {
            User created = theSecurityService.register(newUser);
            created.setPassword(null);
            return ResponseEntity.status(HttpStatus.CREATED).body(created);
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Autentica un usuario mediante email y contraseña.
     * 
     * Si las credenciales son válidas, retorna un token JWT que debe incluirse
     * en el header Authorization de las peticiones subsecuentes.
     * 
     * Campos requeridos en el body:
     * - email: Correo electrónico del usuario
     * - password: Contraseña
     * 
     * @param theUser Objeto User con email y contraseña
     * @return ResponseEntity con el token JWT o mensaje de error
     */
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
