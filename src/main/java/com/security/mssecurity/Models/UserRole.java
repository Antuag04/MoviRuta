package com.security.mssecurity.Models;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework.data.mongodb.core.mapping.Document;

/**
 * Entidad de relación que asocia un usuario con un rol específico.
 * 
 * Esta entidad implementa la relación muchos-a-muchos entre User y Role,
 * permitiendo que un usuario tenga múltiples roles y que un rol pueda
 * ser asignado a múltiples usuarios.
 * 
 * Al registrarse, los usuarios reciben automáticamente el rol "CIUDADANO".
 * Los administradores pueden asignar roles adicionales según sea necesario.
 * 
 * @see User
 * @see Role
 * @see com.security.mssecurity.Services.SecurityService
 */
@Data
@Document
public class UserRole {

    @Id
    private String id;

    /**
     * Referencia al usuario que posee el rol.
     */
    @DBRef
    private User user;

    /**
     * Referencia al rol asignado al usuario.
     */
    @DBRef
    private Role role;

    /**
     * Constructor por defecto requerido por Spring Data MongoDB.
     */
    public UserRole() {
    }

    /**
     * Constructor con parámetros para crear una nueva asignación usuario-rol.
     * 
     * @param user Usuario que recibirá el rol
     * @param role Rol a asignar al usuario
     */
    public UserRole(User user, Role role) {
        this.user = user;
        this.role = role;
    }
}
