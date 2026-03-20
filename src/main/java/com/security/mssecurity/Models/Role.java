package com.security.mssecurity.Models;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

/**
 * Entidad que representa un rol dentro del sistema de control de acceso.
 * 
 * Los roles agrupan un conjunto de permisos y se asignan a los usuarios
 * para definir qué acciones pueden realizar en el sistema.
 * 
 * Ejemplo de roles típicos:
 * - ADMINISTRADOR: Acceso completo al sistema
 * - CIUDADANO: Rol básico asignado automáticamente al registrarse
 * - MODERADOR: Permisos intermedios de gestión
 * 
 * La relación con permisos se gestiona mediante la entidad {@link RolePermission}.
 * La asignación a usuarios se gestiona mediante la entidad {@link UserRole}.
 * 
 * @see RolePermission
 * @see UserRole
 */
@Data
@Document
public class Role {

    @Id
    private String id;

    /**
     * Nombre identificador del rol (ej: "ADMINISTRADOR", "CIUDADANO").
     */
    private String name;

    /**
     * Descripción detallada del propósito y alcance del rol.
     */
    private String description;

    /**
     * Constructor por defecto requerido por Spring Data MongoDB.
     */
    public Role() {
    }

    /**
     * Constructor con parámetros para crear un nuevo rol.
     * 
     * @param name        Nombre identificador del rol
     * @param description Descripción del propósito del rol
     */
    public Role(String name, String description) {
        this.name = name;
        this.description = description;
    }
}
