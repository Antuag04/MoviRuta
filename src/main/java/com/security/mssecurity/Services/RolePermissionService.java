package com.security.mssecurity.Services;

import com.security.mssecurity.Models.Permission;
import com.security.mssecurity.Models.Role;
import com.security.mssecurity.Models.RolePermission;
import com.security.mssecurity.Models.UserRole;
import com.security.mssecurity.Repositories.PermissionRepository;
import com.security.mssecurity.Repositories.RolePermissionRepository;
import com.security.mssecurity.Repositories.RoleRepository;
import com.security.mssecurity.Repositories.UserRoleRepository;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class RolePermissionService {

    private static final Logger logger = LoggerFactory.getLogger(RolePermissionService.class);

    @Autowired
    private RolePermissionRepository theRolePermissionRepository;

    @Autowired
    private UserRoleRepository userRoleRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PermissionRepository permissionRepository;

    @Autowired
    private EmailService emailService;

    public List<RolePermission> findAll() {
        return this.theRolePermissionRepository.findAll();
    }

    public RolePermission findById(String id) {
        return this.theRolePermissionRepository.findById(id).orElse(null);
    }

    public RolePermission create(RolePermission newRolePermission) {
        validateRolePermission(newRolePermission);

        String roleId = newRolePermission.getRole().getId();
        String permissionId = newRolePermission.getPermission().getId();

        if (theRolePermissionRepository.getRolePermission(roleId, permissionId) != null) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "La relacion rol-permiso ya existe");
        }

        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Rol no encontrado"));
        Permission permission = permissionRepository.findById(permissionId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Permiso no encontrado"));

        RolePermission rolePermissionToSave = new RolePermission();
        rolePermissionToSave.setRole(role);
        rolePermissionToSave.setPermission(permission);

        RolePermission saved = this.theRolePermissionRepository.save(rolePermissionToSave);
        notifyUsersSafely(saved, "Se actualizo la lista de permisos asociada a tu rol " + role.getName() + ".");
        return saved;
    }

    public RolePermission update(String id, RolePermission newRolePermission) {
        validateRolePermission(newRolePermission);

        RolePermission actualRolePermission = this.theRolePermissionRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Relacion rol-permiso no encontrada"));

        String roleId = newRolePermission.getRole().getId();
        String permissionId = newRolePermission.getPermission().getId();

        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Rol no encontrado"));
        Permission permission = permissionRepository.findById(permissionId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Permiso no encontrado"));

        actualRolePermission.setRole(role);
        actualRolePermission.setPermission(permission);

        RolePermission saved = this.theRolePermissionRepository.save(actualRolePermission);
        notifyUsersSafely(saved, "Se modifico la configuracion de permisos del rol " + role.getName() + ".");
        return saved;
    }

    public void delete(String id) {
        RolePermission theRolePermission = this.theRolePermissionRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Relacion rol-permiso no encontrada"));

        this.theRolePermissionRepository.delete(theRolePermission);
        notifyUsersSafely(theRolePermission, "Se removio un permiso del rol " + theRolePermission.getRole().getName() + ".");
    }

    private void validateRolePermission(RolePermission rolePermission) {
        if (rolePermission.getRole() == null || rolePermission.getRole().getId() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Debe informar un rol valido");
        }
        if (rolePermission.getPermission() == null || rolePermission.getPermission().getId() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Debe informar un permiso valido");
        }
    }

    private void notifyUsers(RolePermission rolePermission, String details) {
        Set<String> notifiedEmails = new LinkedHashSet<>();
        List<UserRole> users = userRoleRepository.getUsersByRole(rolePermission.getRole().getId());

        for (UserRole userRole : users) {
            if (userRole.getUser() == null || userRole.getUser().getEmail() == null) {
                continue;
            }

            if (notifiedEmails.add(userRole.getUser().getEmail())) {
                emailService.sendPermissionChangeNotification(
                        userRole.getUser().getEmail(),
                        userRole.getUser().getName(),
                        details
                );
            }
        }
    }

    private void notifyUsersSafely(RolePermission rolePermission, String details) {
        try {
            notifyUsers(rolePermission, details);
        } catch (Exception ex) {
            logger.warn(
                    "No se pudieron enviar notificaciones por cambio de permisos para rolePermissionId={} roleId={}. La operacion principal ya fue ejecutada.",
                    rolePermission.getId(),
                    rolePermission.getRole() != null ? rolePermission.getRole().getId() : null,
                    ex
            );
        }
    }
}
