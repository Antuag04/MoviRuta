package com.security.mssecurity.Models;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework.data.mongodb.core.mapping.Document;

/**
 * Entidad de relación que asocia un rol con un permiso específico.
 * 
 * Esta entidad implementa la relación muchos-a-muchos entre Role y Permission,
 * permitiendo asignar múltiples permisos a un rol y que un permiso pueda
 * pertenecer a múltiples roles.
 * 
 * El sistema de autorización utiliza esta tabla para verificar si un usuario
 * (a través de sus roles) tiene permiso para acceder a un recurso específico.
 * 
 * @see Role
 * @see Permission
 * @see com.security.mssecurity.Services.ValidatorsService
 */
@Data
@Document
public class RolePermission {

    @Id
    private String id;

    /**
     * Referencia al rol que recibe el permiso.
     */
    @DBRef
    private Role role;

    /**
     * Referencia al permiso asignado al rol.
     */
    @DBRef
    private Permission permission;

    /**
     * Constructor por defecto requerido por Spring Data MongoDB.
     */
    public RolePermission() {
    }

    /**
     * Constructor con parámetros para crear una nueva asignación rol-permiso.
     * 
     * @param role       Rol que recibirá el permiso
     * @param permission Permiso a asignar
     * @param id         Identificador único de la relación
     */
    public RolePermission(Role role, Permission permission, String id) {
        this.id = id;
        this.role = role;
        this.permission = permission;
    }
}