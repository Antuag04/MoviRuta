package com.security.mssecurity.Services;

import com.security.mssecurity.Models.Role;
import com.security.mssecurity.Repositories.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Servicio que gestiona las operaciones CRUD de roles.
 * 
 * Los roles son componentes fundamentales del sistema RBAC,
 * agrupando permisos que luego se asignan a usuarios.
 * 
 * @see RoleRepository
 * @see com.security.mssecurity.Models.Role
 */
@Service
public class RoleService {

    @Autowired
    private RoleRepository roleRepository;

    /**
     * Obtiene la lista de todos los roles.
     * 
     * @return Lista de roles
     */
    public List<Role> find() {
        return this.roleRepository.findAll();
    }

    /**
     * Busca un rol por su identificador.
     * 
     * @param id Identificador único del rol
     * @return Rol encontrado o null si no existe
     */
    public Role findById(String id) {
        return this.roleRepository.findById(id).orElse(null);
    }

    /**
     * Crea un nuevo rol.
     * 
     * @param newRole Datos del nuevo rol
     * @return Rol creado con su ID asignado
     */
    public Role create(Role newRole) {
        return this.roleRepository.save(newRole);
    }

    /**
     * Actualiza un rol existente.
     * 
     * @param id      Identificador del rol a actualizar
     * @param newRole Datos actualizados
     * @return Rol actualizado o null si no existe
     */
    public Role update(String id, Role newRole) {
        Role actualRole = this.roleRepository.findById(id).orElse(null);

        if (actualRole != null) {
            actualRole.setName(newRole.getName());
            actualRole.setDescription(newRole.getDescription());
            this.roleRepository.save(actualRole);
            return actualRole;
        } else {
            return null;
        }
    }

    /**
     * Elimina un rol del sistema.
     * 
     * @param id Identificador del rol a eliminar
     */
    public void delete(String id) {
        Role theRole = this.roleRepository.findById(id).orElse(null);
        if (theRole != null) {
            this.roleRepository.delete(theRole);
        }
    }
}
