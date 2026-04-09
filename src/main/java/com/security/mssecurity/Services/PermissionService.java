package com.security.mssecurity.Services;

import com.security.mssecurity.Models.Permission;
import com.security.mssecurity.Models.RolePermission;
import com.security.mssecurity.Models.UserRole;
import com.security.mssecurity.Repositories.PermissionRepository;
import com.security.mssecurity.Repositories.RolePermissionRepository;
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
public class PermissionService {

    private static final Logger logger = LoggerFactory.getLogger(PermissionService.class);

    @Autowired
    private PermissionRepository permissionRepository;

    @Autowired
    private RolePermissionRepository rolePermissionRepository;

    @Autowired
    private UserRoleRepository userRoleRepository;

    @Autowired
    private EmailService emailService;

    public List<Permission> find() {
        return this.permissionRepository.findAll();
    }

    public Permission findById(String id) {
        return this.permissionRepository.findById(id).orElse(null);
    }

    public Permission create(Permission newPermission) {
        return this.permissionRepository.save(newPermission);
    }

    public Permission update(String id, Permission newPermission) {
        Permission actualPermission = this.permissionRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Permiso no encontrado"));

        actualPermission.setUrl(newPermission.getUrl());
        actualPermission.setMethod(newPermission.getMethod());
        actualPermission.setModel(newPermission.getModel());
        Permission saved = this.permissionRepository.save(actualPermission);

        notifyUsersSafely(saved.getId(), "Se actualizo la definicion de uno de tus permisos.");
        return saved;
    }

    public void delete(String id) {
        Permission thePermission = this.permissionRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Permiso no encontrado"));

        List<RolePermission> relations = rolePermissionRepository.getRolesByPermission(id);
        if (!relations.isEmpty()) {
            rolePermissionRepository.deleteAll(relations);
        }
        this.permissionRepository.delete(thePermission);
        notifyUsersSafely(id, "Se elimino uno de los permisos asignados a tus roles.");
    }

    private void notifyUsers(String permissionId, String details) {
        Set<String> notifiedEmails = new LinkedHashSet<>();
        List<RolePermission> relations = rolePermissionRepository.getRolesByPermission(permissionId);

        for (RolePermission relation : relations) {
            List<UserRole> users = userRoleRepository.getUsersByRole(relation.getRole().getId());
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
    }

    private void notifyUsersSafely(String permissionId, String details) {
        try {
            notifyUsers(permissionId, details);
        } catch (Exception ex) {
            logger.warn(
                    "No se pudieron enviar notificaciones por cambio en permissionId={}. La operacion principal ya fue ejecutada.",
                    permissionId,
                    ex
            );
        }
    }
}
