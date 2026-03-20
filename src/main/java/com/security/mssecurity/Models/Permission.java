package com.security.mssecurity.Models;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

/**
 * Entidad que representa un permiso de acceso a un recurso específico del sistema.
 * 
 * Los permisos definen qué endpoints HTTP pueden ser accedidos y con qué métodos.
 * Se asocian a roles mediante la entidad {@link RolePermission}, implementando
 * así un sistema de control de acceso basado en roles (RBAC).
 * 
 * Cada permiso está compuesto por:
 * - URL: Ruta del endpoint (los IDs se representan con "?")
 * - Método HTTP: GET, POST, PUT, DELETE
 * - Modelo: Entidad a la que pertenece el recurso
 * 
 * Ejemplo:
 * - url: "/api/users/?"
 * - method: "GET"
 * - model: "User"
 * 
 * @see RolePermission
 */
@Data
@Document
public class Permission {

    @Id
    private String id;

    /**
     * Ruta del endpoint protegido.
     * Los segmentos dinámicos (IDs) se representan con "?".
     * Ejemplo: "/api/users/?", "/api/roles"
     */
    private String url;

    /**
     * Método HTTP permitido: GET, POST, PUT, DELETE.
     */
    private String method;

    /**
     * Nombre de la entidad o módulo al que pertenece el permiso.
     * Útil para agrupar y organizar los permisos.
     * Ejemplo: "User", "Role", "Session"
     */
    private String model;

    /**
     * Constructor por defecto requerido por Spring Data MongoDB.
     */
    public Permission() {
    }

    /**
     * Constructor con parámetros para crear un nuevo permiso.
     * 
     * @param url    Ruta del endpoint
     * @param method Método HTTP permitido
     * @param model  Entidad a la que pertenece el recurso
     */
    public Permission(String url, String method, String model) {
        this.url = url;
        this.method = method;
        this.model = model;
    }
}