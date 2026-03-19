package com.security.mssecurity.Services;

import com.security.mssecurity.Models.RolePermission;
import com.security.mssecurity.Repositories.RolePermissionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.List;

@Service
public class RolePermissionService {

    @Autowired
    private RolePermissionRepository theRolePermissionRepository;

    public List<RolePermission> findAll() {
        return this.theRolePermissionRepository.findAll();
    }

    public RolePermission findById(String id) {
        return this.theRolePermissionRepository.findById(id).orElse(null);
    }

    public RolePermission create(RolePermission newRolePermission) {
        return this.theRolePermissionRepository.save(newRolePermission);
    }

    public RolePermission update(String id, RolePermission newRolePermission) {
        RolePermission actualRolePermission = this.theRolePermissionRepository.findById(id).orElse(null);

        if (actualRolePermission != null) {
            actualRolePermission.setRole(newRolePermission.getRole());
            actualRolePermission.setPermission(newRolePermission.getPermission());
            // Si el modelo tuviera más campos, se actualizarían aquí
            return this.theRolePermissionRepository.save(actualRolePermission);
        } else {
            return null;
        }
    }

    public void delete(String id) {
        RolePermission theRolePermission = this.theRolePermissionRepository.findById(id).orElse(null);
        if (theRolePermission != null) {
            this.theRolePermissionRepository.delete(theRolePermission);
        }
    }
}