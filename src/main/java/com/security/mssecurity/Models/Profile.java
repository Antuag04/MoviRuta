package com.security.mssecurity.Models;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework.data.mongodb.core.mapping.Document;

/**
 * Entidad que almacena información adicional del perfil de un usuario.
 * 
 * Separa los datos de autenticación (User) de los datos de perfil,
 * permitiendo una gestión independiente de la información personal
 * del usuario.
 * 
 * Relación: Un usuario puede tener un perfil asociado (relación 1:1).
 * 
 * @see User
 */
@Data
@Document
public class Profile {

    @Id
    private String id;

    /**
     * Número de teléfono del usuario.
     */
    private String phone;

    /**
     * URL o ruta de la fotografía de perfil del usuario.
     */
    private String photo;

    /**
     * Referencia al usuario propietario del perfil.
     */
    @DBRef
    private User user;

    /**
     * Constructor por defecto requerido por Spring Data MongoDB.
     */
    public Profile() {
    }

    /**
     * Constructor con parámetros para crear un nuevo perfil.
     * 
     * @param phone Número de teléfono
     * @param photo URL de la fotografía de perfil
     */
    public Profile(String phone, String photo) {
        this.phone = phone;
        this.photo = photo;
    }
}
