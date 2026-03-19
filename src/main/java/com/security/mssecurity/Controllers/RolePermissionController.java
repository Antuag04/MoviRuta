package com.security.mssecurity.Controllers;

import com.security.mssecurity.Models.RolePermission;
import com.security.mssecurity.Services.RolePermissionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin
@RestController
@RequestMapping("/role-permissions")
public class RolePermissionController {

    @Autowired
    private RolePermissionService theRolePermissionService;

    @GetMapping("")
    public List<RolePermission> findAll() {
        return this.theRolePermissionService.findAll();
    }

    @GetMapping("{id}")
    public RolePermission findById(@PathVariable String id) {
        return this.theRolePermissionService.findById(id);
    }

    @PostMapping
    public RolePermission create(@RequestBody RolePermission newRolePermission) {
        return this.theRolePermissionService.create(newRolePermission);
    }

    @PutMapping("{id}")
    public RolePermission update(@PathVariable String id, @RequestBody RolePermission newRolePermission) {
        return this.theRolePermissionService.update(id, newRolePermission);
    }

    @DeleteMapping("{id}")
    public void delete(@PathVariable String id) {
        this.theRolePermissionService.delete(id);
    }
}