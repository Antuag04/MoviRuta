package com.security.mssecurity.Services;

import com.security.mssecurity.Models.Permission;
import com.security.mssecurity.Repositories.PermissionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Servicio que gestiona las operaciones CRUD de permisos.
 * 
 * Los permisos definen qué recursos (URL + método HTTP) están protegidos
 * en el sistema y se asignan a roles mediante RolePermission.
 * 
 * @see PermissionRepository
 * @see com.security.mssecurity.Models.Permission
 */
@Service
public class PermissionService {

    @Autowired
    private PermissionRepository permissionRepository;

    /**
     * Obtiene la lista de todos los permisos.
     * 
     * @return Lista de permisos
     */
    public List<Permission> find() {
        return this.permissionRepository.findAll();
    }

    /**
     * Busca un permiso por su identificador.
     * 
     * @param id Identificador único del permiso
     * @return Permiso encontrado o null si no existe
     */
    public Permission findById(String id) {
        return this.permissionRepository.findById(id).orElse(null);
    }

    /**
     * Crea un nuevo permiso.
     * 
     * @param newPermission Datos del nuevo permiso (url, method, model)
     * @return Permiso creado con su ID asignado
     */
    public Permission create(Permission newPermission) {
        return this.permissionRepository.save(newPermission);
    }

    /**
     * Actualiza un permiso existente.
     * 
     * @param id            Identificador del permiso a actualizar
     * @param newPermission Datos actualizados
     * @return Permiso actualizado o null si no existe
     */
    public Permission update(String id, Permission newPermission) {
        Permission actualPermission = this.permissionRepository.findById(id).orElse(null);

        if (actualPermission != null) {
            actualPermission.setUrl(newPermission.getUrl());
            actualPermission.setMethod(newPermission.getMethod());
            actualPermission.setModel(newPermission.getModel());
            this.permissionRepository.save(actualPermission);
            return actualPermission;
        } else {
            return null;
        }
    }

    /**
     * Elimina un permiso del sistema.
     * 
     * @param id Identificador del permiso a eliminar
     */
    public void delete(String id) {
        Permission thePermission = this.permissionRepository.findById(id).orElse(null);
        if (thePermission != null) {
            this.permissionRepository.delete(thePermission);
        }
    }
}