package com.security.mssecurity.Models;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

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
