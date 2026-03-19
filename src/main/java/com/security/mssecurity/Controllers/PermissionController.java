package com.security.mssecurity.Controllers;

import com.security.mssecurity.Models.Permission;
import com.security.mssecurity.Services.PermissionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin
@RestController
@RequestMapping("/permissions")
public class PermissionController {

    @Autowired
    private PermissionService permissionService;

    @GetMapping
    public List<Permission> find() {
        return this.permissionService.find();
    }

    @GetMapping("/{id}")
    public Permission findById(@PathVariable String id) {
        return this.permissionService.findById(id);
    }

    @PostMapping
    public Permission create(@RequestBody Permission newPermission) {
        return this.permissionService.create(newPermission);
    }

    @PutMapping("/{id}")
    public Permission update(@PathVariable String id, @RequestBody Permission newPermission) {
        return this.permissionService.update(id, newPermission);
    }

    @DeleteMapping("/{id}")
    public void delete(@PathVariable String id) {
        this.permissionService.delete(id);
    }
}