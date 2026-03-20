package com.security.mssecurity.Controllers;

import com.security.mssecurity.Models.RolePermission;
import com.security.mssecurity.Services.RolePermissionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Controlador REST para la gestión de asignaciones rol-permiso.
 * 
 * Este controlador expone endpoints protegidos bajo /api/role-permissions que
 * permiten administrar las relaciones entre roles y permisos, fundamentales
 * para el sistema de control de acceso basado en roles (RBAC).
 * 
 * Cada RolePermission vincula un Role con un Permission, indicando que
 * los usuarios con ese rol tienen autorización para acceder al recurso
 * definido por el permiso.
 * 
 * @see RolePermissionService
 * @see com.security.mssecurity.Models.RolePermission
 */
@CrossOrigin
@RestController
@RequestMapping("api/role-permissions")
public class RolePermissionController {

    @Autowired
    private RolePermissionService theRolePermissionService;

    /**
     * Obtiene la lista de todas las asignaciones rol-permiso.
     * 
     * @return Lista de objetos RolePermission con sus referencias a Role y Permission
     */
    @GetMapping("")
    public List<RolePermission> findAll() {
        return this.theRolePermissionService.findAll();
    }

    /**
     * Obtiene una asignación rol-permiso específica por su identificador.
     * 
     * @param id Identificador único de la asignación (ObjectId de MongoDB)
     * @return Objeto RolePermission o null si no existe
     */
    @GetMapping("{id}")
    public RolePermission findById(@PathVariable String id) {
        return this.theRolePermissionService.findById(id);
    }

    /**
     * Crea una nueva asignación rol-permiso.
     * 
     * El body debe incluir referencias válidas a Role y Permission existentes.
     * 
     * @param newRolePermission Objeto RolePermission con las referencias
     * @return Asignación creada con su ID asignado
     */
    @PostMapping
    public RolePermission create(@RequestBody RolePermission newRolePermission) {
        return this.theRolePermissionService.create(newRolePermission);
    }

    /**
     * Actualiza una asignación rol-permiso existente.
     * 
     * @param id                Identificador único de la asignación
     * @param newRolePermission Objeto RolePermission con los datos actualizados
     * @return Asignación actualizada
     */
    @PutMapping("{id}")
    public RolePermission update(@PathVariable String id, @RequestBody RolePermission newRolePermission) {
        return this.theRolePermissionService.update(id, newRolePermission);
    }

    /**
     * Elimina una asignación rol-permiso.
     * 
     * Al eliminar esta asignación, los usuarios con el rol asociado
     * perderán acceso al recurso definido por el permiso.
     * 
     * @param id Identificador único de la asignación a eliminar
     */
    @DeleteMapping("{id}")
    public void delete(@PathVariable String id) {
        this.theRolePermissionService.delete(id);
    }
}