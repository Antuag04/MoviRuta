package com.security.mssecurity.Repositories;

import com.security.mssecurity.Models.Role;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;

/**
 * Repositorio para acceso a datos de la colección de roles en MongoDB.
 * 
 * Proporciona operaciones CRUD básicas y consultas personalizadas
 * para la gestión de roles del sistema.
 * 
 * @see Role
 */
@Repository
public interface RoleRepository extends MongoRepository<Role, String> {
    
    /**
     * Busca un rol por su nombre (case-insensitive).
     * 
     * Utiliza expresión regular para hacer la búsqueda insensible
     * a mayúsculas/minúsculas, permitiendo encontrar "CIUDADANO",
     * "ciudadano" o "Ciudadano" indistintamente.
     * 
     * @param name Nombre del rol a buscar
     * @return Rol encontrado o null si no existe
     */
    @Query("{'name': {$regex: ?0, $options: 'i'}}")
    Role findByName(String name);
}
