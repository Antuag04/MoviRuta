package com.security.mssecurity.Repositories;

import com.security.mssecurity.Models.Permission;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;

/**
 * Repositorio para acceso a datos de la colección de permisos en MongoDB.
 * 
 * Proporciona operaciones CRUD básicas y consultas personalizadas
 * para la validación de permisos en el sistema de control de acceso.
 * 
 * @see Permission
 */
public interface PermissionRepository extends MongoRepository<Permission, String> {
    
    /**
     * Busca un permiso por URL y método HTTP.
     * 
     * Esta consulta es fundamental para el sistema de autorización,
     * permitiendo verificar si existe un permiso definido para un
     * recurso específico (combinación de URL + método HTTP).
     * 
     * @param url    URL del recurso (ej: "/api/users/?")
     * @param method Método HTTP (GET, POST, PUT, DELETE)
     * @return Permiso encontrado o null si no existe
     */
    @Query("{'url':?0,'method':?1}")
    Permission getPermission(String url, String method);
}