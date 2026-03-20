package com.security.mssecurity.Services;

import com.security.mssecurity.Models.RolePermission;
import com.security.mssecurity.Repositories.RolePermissionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.List;

/**
 * Servicio que gestiona las operaciones CRUD de asignaciones rol-permiso.
 * 
 * Las asignaciones RolePermission vinculan roles con permisos específicos,
 * definiendo qué acciones puede realizar cada rol en el sistema.
 * 
 * @see RolePermissionRepository
 * @see com.security.mssecurity.Models.RolePermission
 */
@Service
public class RolePermissionService {

    @Autowired
    private RolePermissionRepository theRolePermissionRepository;

    /**
     * Obtiene la lista de todas las asignaciones rol-permiso.
     * 
     * @return Lista de asignaciones
     */
    public List<RolePermission> findAll() {
        return this.theRolePermissionRepository.findAll();
    }

    /**
     * Busca una asignación por su identificador.
     * 
     * @param id Identificador único de la asignación
     * @return Asignación encontrada o null si no existe
     */
    public RolePermission findById(String id) {
        return this.theRolePermissionRepository.findById(id).orElse(null);
    }

    /**
     * Crea una nueva asignación rol-permiso.
     * 
     * @param newRolePermission Datos de la nueva asignación
     * @return Asignación creada con su ID asignado
     */
    public RolePermission create(RolePermission newRolePermission) {
        return this.theRolePermissionRepository.save(newRolePermission);
    }

    /**
     * Actualiza una asignación existente.
     * 
     * @param id                Identificador de la asignación a actualizar
     * @param newRolePermission Datos actualizados
     * @return Asignación actualizada o null si no existe
     */
    public RolePermission update(String id, RolePermission newRolePermission) {
        RolePermission actualRolePermission = this.theRolePermissionRepository.findById(id).orElse(null);

        if (actualRolePermission != null) {
            actualRolePermission.setRole(newRolePermission.getRole());
            actualRolePermission.setPermission(newRolePermission.getPermission());
            return this.theRolePermissionRepository.save(actualRolePermission);
        } else {
            return null;
        }
    }

    /**
     * Elimina una asignación rol-permiso.
     * 
     * @param id Identificador de la asignación a eliminar
     */
    public void delete(String id) {
        RolePermission theRolePermission = this.theRolePermissionRepository.findById(id).orElse(null);
        if (theRolePermission != null) {
            this.theRolePermissionRepository.delete(theRolePermission);
        }
    }
}