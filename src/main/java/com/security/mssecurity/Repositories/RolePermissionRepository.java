package com.security.mssecurity.Repositories;

import com.security.mssecurity.Models.RolePermission;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;

import java.util.List;

/**
 * Repositorio para acceso a datos de la colección de asignaciones rol-permiso en MongoDB.
 * 
 * Proporciona operaciones CRUD básicas y consultas personalizadas para
 * verificar los permisos asignados a cada rol en el sistema RBAC.
 * 
 * @see RolePermission
 */
public interface RolePermissionRepository extends MongoRepository<RolePermission, String> {
    
    /**
     * Obtiene todos los permisos asignados a un rol específico.
     * 
     * Utiliza DBRef para navegar la relación con la colección de roles.
     * 
     * @param roleId Identificador del rol (ObjectId)
     * @return Lista de asignaciones RolePermission para el rol especificado
     */
    @Query("{'role.$id': ObjectId(?0)}")
    List<RolePermission> getPermissionsByRole(String roleId);
    
    /**
     * Verifica si existe una asignación específica rol-permiso.
     * 
     * Esta consulta es utilizada por el sistema de autorización para
     * determinar si un rol tiene un permiso específico asignado.
     * 
     * @param roleId       Identificador del rol (ObjectId)
     * @param permissionId Identificador del permiso (ObjectId)
     * @return Asignación encontrada o null si no existe
     */
    @Query("{'role.$id': ObjectId(?0),'permission.$id': ObjectId(?1)}")
    public RolePermission getRolePermission(String roleId, String permissionId);

    @Query("{'permission.$id': ObjectId(?0)}")
    List<RolePermission> getRolesByPermission(String permissionId);
}
