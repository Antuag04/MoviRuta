package com.security.mssecurity.Repositories;

import com.security.mssecurity.Models.UserRole;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;

import java.util.List;

/**
 * Repositorio para acceso a datos de la colección de asignaciones usuario-rol en MongoDB.
 * 
 * Proporciona operaciones CRUD básicas y consultas personalizadas para
 * obtener los roles asignados a cada usuario en el sistema RBAC.
 * 
 * @see UserRole
 */
public interface UserRoleRepository extends MongoRepository<UserRole, String> {
    
    /**
     * Obtiene todos los roles asignados a un usuario específico.
     * 
     * Esta consulta es fundamental para el sistema de autorización,
     * permitiendo determinar qué roles tiene un usuario y, por extensión,
     * qué permisos le corresponden.
     * 
     * Utiliza DBRef para navegar la relación con la colección de usuarios.
     * 
     * @param userId Identificador del usuario (ObjectId)
     * @return Lista de asignaciones UserRole para el usuario especificado
     */
    @Query("{ 'user.$id' : ObjectId(?0) }")
    public List<UserRole> getRolesByUser(String userId);

    @Query("{ 'role.$id' : ObjectId(?0) }")
    public List<UserRole> getUsersByRole(String roleId);

    @Query("{ 'user.$id' : ObjectId(?0), 'role.$id' : ObjectId(?1) }")
    public UserRole getUserRole(String userId, String roleId);
}
