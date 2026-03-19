package com.security.mssecurity.Services;

import com.security.mssecurity.Models.Permission;
import com.security.mssecurity.Repositories.PermissionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class PermissionService {

    @Autowired
    private PermissionRepository permissionRepository;

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

    public void delete(String id) {
        Permission thePermission = this.permissionRepository.findById(id).orElse(null);
        if (thePermission != null) {
            this.permissionRepository.delete(thePermission);
        }
    }
}