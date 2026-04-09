package com.security.mssecurity.Models;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.LocalDateTime;

/**
 * Entidad que representa un usuario del sistema.
 * 
 * Esta clase almacena la información básica de autenticación de los usuarios,
 * soportando tanto el registro tradicional (email/contraseña) como la
 * autenticación mediante proveedores OAuth 2.0 (Google, GitHub, Microsoft).
 * 
 * El campo authProvider indica el método de registro utilizado:
 * - "LOCAL"     : Registro tradicional con contraseña
 * - "GOOGLE"    : Autenticación mediante Google OAuth 2.0
 * - "GITHUB"    : Autenticación mediante GitHub OAuth 2.0
 * - "MICROSOFT" : Autenticación mediante Microsoft OAuth 2.0
 * 
 * Para usuarios OAuth, el campo password es null ya que la autenticación
 * es delegada al proveedor externo.
 * 
 * Adicionalmente, esta entidad almacena datos temporales para:
 * - Autenticación de dos factores (2FA): código y expiración
 * - Recuperación de contraseña: token y expiración
 */
@Data
@Document
public class User {

    @Id
    private String id;

    private String name;

    private String email;

    private String password;

    /**
     * Proveedor de autenticación utilizado para registrar al usuario.
     * Valores posibles: "LOCAL", "GOOGLE", "GITHUB", "MICROSOFT"
     */
    private String authProvider;

    // =========================================================================
    // CAMPOS PARA AUTENTICACIÓN DE DOS FACTORES (2FA)
    // =========================================================================

    /**
     * Código de verificación de 6 dígitos para autenticación de dos factores.
     * 
     * Este código se genera cuando el usuario inicia sesión correctamente
     * y se envía a su correo electrónico. El usuario debe ingresar este
     * código para completar el proceso de autenticación.
     * 
     * Se establece en null después de ser utilizado o cuando expira.
     */
    private String twoFactorCode;

    /**
     * Fecha y hora de expiración del código 2FA.
     * 
     * Por defecto, el código expira 5 minutos después de ser generado.
     * Si el usuario intenta verificar después de esta fecha, el código
     * se considera inválido.
     */
    private LocalDateTime twoFactorExpiry;

    private Integer twoFactorAttempts;

    // =========================================================================
    // CAMPOS PARA RECUPERACIÓN DE CONTRASEÑA
    // =========================================================================

    /**
     * Token único (UUID) para recuperación de contraseña.
     * 
     * Se genera cuando el usuario solicita restablecer su contraseña
     * y se envía como parte de un enlace a su correo electrónico.
     * El formato es UUID v4 (ej: "550e8400-e29b-41d4-a716-446655440000").
     * 
     * Se establece en null después de ser utilizado o cuando expira.
     */
    private String resetToken;

    /**
     * Fecha y hora de expiración del token de recuperación.
     * 
     * Por defecto, el token expira 30 minutos después de ser generado.
     * Esto limita la ventana de tiempo en la que un enlace de
     * recuperación es válido, mejorando la seguridad.
     */
    private LocalDateTime resetTokenExpiry;

    /**
     * Constructor por defecto requerido por Spring Data MongoDB.
     */
    public User() {
    }

    /**
     * Constructor para registro tradicional (con contraseña).
     * Establece automáticamente authProvider como "LOCAL".
     * 
     * @param name     Nombre completo del usuario
     * @param email    Correo electrónico (identificador único)
     * @param password Contraseña (será encriptada antes de almacenar)
     */
    public User(String name, String email, String password) {
        this.name = name;
        this.email = email;
        this.password = password;
        this.authProvider = "LOCAL";
    }

    /**
     * Constructor para usuarios autenticados mediante OAuth 2.0.
     * No requiere contraseña ya que la autenticación es delegada
     * al proveedor externo.
     * 
     * @param name         Nombre completo obtenido del proveedor OAuth
     * @param email        Correo electrónico obtenido del proveedor OAuth
     * @param authProvider Identificador del proveedor ("GOOGLE", "GITHUB", "MICROSOFT")
     * @param isOAuth      Flag para distinguir este constructor del tradicional
     */
    public User(String name, String email, String authProvider, boolean isOAuth) {
        this.name = name;
        this.email = email;
        this.password = null;
        this.authProvider = authProvider;
    }
}
