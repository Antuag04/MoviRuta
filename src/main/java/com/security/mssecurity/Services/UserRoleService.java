package com.security.mssecurity.Services;

import com.security.mssecurity.Models.Role;
import com.security.mssecurity.Models.User;
import com.security.mssecurity.Models.UserRole;
import com.security.mssecurity.Repositories.RoleRepository;
import com.security.mssecurity.Repositories.UserRepository;
import com.security.mssecurity.Repositories.UserRoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * Servicio que gestiona las asignaciones de roles a usuarios.
 * 
 * Este servicio permite asignar y revocar roles a usuarios,
 * controlando los permisos que cada usuario tiene en el sistema.
 * 
 * @see UserRoleRepository
 * @see com.security.mssecurity.Models.UserRole
 */
@Service
public class UserRoleService {

    @Autowired
    private UserRepository theUserRepository;

    @Autowired
    private RoleRepository theRoleRepository;

    @Autowired
    private UserRoleRepository theUserRoleRepository;

    /**
     * Asigna un rol a un usuario.
     * 
     * Crea una nueva relación UserRole entre el usuario y el rol.
     * Ambas entidades deben existir previamente.
     * 
     * @param userId Identificador del usuario
     * @param roleId Identificador del rol a asignar
     * @return true si la asignación fue exitosa, false si no se encontraron las entidades
     */
    public boolean addUserRole(String userId, String roleId) {
        User user = this.theUserRepository.findById(userId).orElse(null);
        Role role = this.theRoleRepository.findById(roleId).orElse(null);
        
        if (user != null && role != null) {
            UserRole theUserRole = new UserRole(user, role);
            this.theUserRoleRepository.save(theUserRole);
            return true;
        } else {
            return false;
        }
    }

    /**
     * Revoca un rol de un usuario eliminando la asignación.
     * 
     * @param userRoleId Identificador de la asignación UserRole
     * @return true si la operación fue exitosa, false si no se encontró la asignación
     */
    public boolean removeUserRole(String userRoleId) {
        UserRole userRole = this.theUserRoleRepository.findById(userRoleId).orElse(null);
        
        if (userRole != null) {
            this.theUserRoleRepository.delete(userRole);
            return true;
        } else {
            return false;
        }
    }
}

