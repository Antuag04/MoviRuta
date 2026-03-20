package com.security.mssecurity.Models;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.Date;

/**
 * Entidad que representa una sesión de usuario activa en el sistema.
 * 
 * Almacena información sobre las sesiones de autenticación, incluyendo
 * el token JWT generado, su fecha de expiración y opcionalmente un
 * código de autenticación de dos factores (2FA).
 * 
 * La sesión está vinculada a un usuario específico mediante una
 * referencia de base de datos (@DBRef).
 * 
 * @see User
 */
@Data
@Document
public class Session {

    @Id
    private String id;

    /**
     * Token JWT asociado a la sesión.
     */
    private String token;

    /**
     * Fecha y hora de expiración del token.
     */
    private Date expiration;

    /**
     * Código de autenticación de dos factores (opcional).
     * Utilizado cuando se implementa 2FA en el sistema.
     */
    private String code2FA;

    /**
     * Referencia al usuario propietario de la sesión.
     * Se almacena como referencia en MongoDB para mantener la integridad.
     */
    @DBRef
    private User user;

    /**
     * Constructor por defecto requerido por Spring Data MongoDB.
     */
    public Session() {
    }

    /**
     * Constructor con parámetros para crear una nueva sesión.
     * 
     * @param token      Token JWT de la sesión
     * @param expiration Fecha de expiración del token
     * @param code2FA    Código de autenticación 2FA (puede ser null)
     */
    public Session(String token, Date expiration, String code2FA) {
        this.token = token;
        this.expiration = expiration;
        this.code2FA = code2FA;
    }
}
