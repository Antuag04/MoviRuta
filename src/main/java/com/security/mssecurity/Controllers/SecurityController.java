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
 * - POST /login: Inicio de sesión con reCAPTCHA y 2FA
 * - POST /verify-2fa: Verificación del código 2FA
 * - POST /forgot-password: Solicitud de recuperación de contraseña
 * - POST /reset-password: Restablecimiento de contraseña con token
 * 
 * Todos estos endpoints son públicos y no requieren autenticación previa.
 * 
 * Flujo de autenticación:
 * 1. login (email + password + reCAPTCHA) → Envía código 2FA
 * 2. verify-2fa (email + código) → Retorna JWT
 * 
 * Flujo de recuperación:
 * 1. forgot-password (email + reCAPTCHA) → Envía enlace
 * 2. reset-password (token + newPassword) → Actualiza contraseña
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
     * Inicia el proceso de autenticación con verificación en dos pasos.
     * 
     * Este endpoint implementa la primera fase del login seguro:
     * 1. Valida el token reCAPTCHA con Google
     * 2. Verifica las credenciales (email/password)
     * 3. Genera y envía código 2FA al correo del usuario
     * 
     * El frontend debe manejar la respuesta y mostrar el formulario
     * de ingreso del código 2FA cuando "requires2FA" sea true.
     * 
     * Campos requeridos en el body:
     * - email: Correo electrónico del usuario
     * - password: Contraseña del usuario
     * - recaptchaToken: Token generado por reCAPTCHA v3
     * 
     * @param request Map con email, password y recaptchaToken
     * @return ResponseEntity con { "requires2FA": true } o mensaje de error
     */
    @PostMapping("login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> request) {
        try {
            String email = request.get("email");
            String password = request.get("password");
            String recaptchaToken = request.get("recaptchaToken");

            Map<String, Object> result = theSecurityService.login(email, password, recaptchaToken);
            return ResponseEntity.ok(result);

        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Verifica el código 2FA y completa la autenticación.
     * 
     * Este endpoint implementa la segunda fase del login seguro:
     * 1. Valida que el código coincida con el enviado por email
     * 2. Verifica que el código no haya expirado (5 minutos)
     * 3. Genera y retorna el token JWT
     * 
     * Campos requeridos en el body:
     * - email: Correo electrónico del usuario
     * - code: Código de 6 dígitos recibido por email
     * 
     * @param request Map con email y code
     * @return ResponseEntity con { "token": "jwt..." } o mensaje de error
     */
    @PostMapping("verify-2fa")
    public ResponseEntity<?> verify2FA(@RequestBody Map<String, String> request) {
        try {
            String email = request.get("email");
            String code = request.get("code");

            String token = theSecurityService.verify2FA(email, code);
            return ResponseEntity.ok(Map.of("token", token));

        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Solicita la recuperación de contraseña.
     * 
     * Este endpoint inicia el flujo de recuperación:
     * 1. Valida el token reCAPTCHA con Google
     * 2. Si el email existe, genera token UUID y envía enlace por correo
     * 3. Por seguridad, siempre responde éxito (no revela si el email existe)
     * 
     * Campos requeridos en el body:
     * - email: Correo electrónico del usuario
     * - recaptchaToken: Token generado por reCAPTCHA v3
     * 
     * @param request Map con email y recaptchaToken
     * @return ResponseEntity con mensaje de confirmación o error
     */
    @PostMapping("forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestBody Map<String, String> request) {
        try {
            String email = request.get("email");
            String recaptchaToken = request.get("recaptchaToken");

            theSecurityService.forgotPassword(email, recaptchaToken);

            // Siempre responde éxito por seguridad (no revela si el email existe)
            return ResponseEntity.ok(Map.of(
                    "message", "Si el correo está registrado, recibirá un enlace de recuperación"
            ));

        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Restablece la contraseña utilizando el token de recuperación.
     * 
     * Este endpoint completa el flujo de recuperación:
     * 1. Valida que el token exista y no haya expirado (30 minutos)
     * 2. Actualiza la contraseña del usuario
     * 3. Invalida el token (un solo uso)
     * 
     * Campos requeridos en el body:
     * - token: Token UUID recibido en el enlace del correo
     * - newPassword: Nueva contraseña (mínimo 6 caracteres)
     * 
     * @param request Map con token y newPassword
     * @return ResponseEntity con mensaje de confirmación o error
     */
    @PostMapping("reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody Map<String, String> request) {
        try {
            String token = request.get("token");
            String newPassword = request.get("newPassword");

            theSecurityService.resetPassword(token, newPassword);

            return ResponseEntity.ok(Map.of(
                    "message", "Contraseña actualizada exitosamente"
            ));

        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", e.getMessage()));
        }
    }
}
