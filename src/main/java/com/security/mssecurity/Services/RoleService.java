package com.security.mssecurity.Services;

import com.security.mssecurity.Models.Role;
import com.security.mssecurity.Models.RolePermission;
import com.security.mssecurity.Models.UserRole;
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
public class RoleService {

    private static final Logger logger = LoggerFactory.getLogger(RoleService.class);

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private UserRoleRepository userRoleRepository;

    @Autowired
    private RolePermissionRepository rolePermissionRepository;

    @Autowired
    private EmailService emailService;

    public List<Role> find() {
        return this.roleRepository.findAll();
    }

    public Role findById(String id) {
        return this.roleRepository.findById(id).orElse(null);
    }

    public Role create(Role newRole) {
        return this.roleRepository.save(newRole);
    }

    public Role update(String id, Role newRole) {
        Role actualRole = this.roleRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Rol no encontrado"));

        actualRole.setName(newRole.getName());
        actualRole.setDescription(newRole.getDescription());
        Role savedRole = this.roleRepository.save(actualRole);

        notifyUsersSafely(savedRole, "Tu rol " + savedRole.getName() + " fue actualizado.");
        return savedRole;
    }

    public void delete(String id) {
        Role theRole = this.roleRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Rol no encontrado"));

        List<UserRole> associatedUsers = this.userRoleRepository.getUsersByRole(id);
        if (!associatedUsers.isEmpty()) {
            throw new ResponseStatusException(
                    HttpStatus.CONFLICT,
                    "No se puede eliminar el rol porque tiene usuarios asociados"
            );
        }

        List<RolePermission> rolePermissions = rolePermissionRepository.getPermissionsByRole(id);
        if (!rolePermissions.isEmpty()) {
            rolePermissionRepository.deleteAll(rolePermissions);
        }

        this.roleRepository.delete(theRole);
    }

    private void notifyUsers(Role role, String details) {
        Set<String> notifiedEmails = new LinkedHashSet<>();
        List<UserRole> assignments = userRoleRepository.getUsersByRole(role.getId());

        for (UserRole assignment : assignments) {
            if (assignment.getUser() == null || assignment.getUser().getEmail() == null) {
                continue;
            }

            if (notifiedEmails.add(assignment.getUser().getEmail())) {
                emailService.sendRoleChangeNotification(
                        assignment.getUser().getEmail(),
                        assignment.getUser().getName(),
                        details
                );
            }
        }
    }

    private void notifyUsersSafely(Role role, String details) {
        try {
            notifyUsers(role, details);
        } catch (Exception ex) {
            logger.warn(
                    "No se pudieron enviar notificaciones por cambio en roleId={}. La operacion principal ya fue ejecutada.",
                    role.getId(),
                    ex
            );
        }
    }
}
