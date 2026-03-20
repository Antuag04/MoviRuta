package com.security.mssecurity.Controllers;

import com.security.mssecurity.Models.Role;
import com.security.mssecurity.Services.RoleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Controlador REST para la gestión de roles del sistema.
 * 
 * Este controlador expone endpoints protegidos bajo /api/roles que permiten
 * administrar los roles utilizados en el sistema de control de acceso basado
 * en roles (RBAC).
 * 
 * Los roles agrupan permisos y se asignan a usuarios para definir qué
 * acciones pueden realizar en el sistema.
 * 
 * @see RoleService
 * @see com.security.mssecurity.Models.Role
 */
@CrossOrigin
@RestController
@RequestMapping("/api/roles")
public class RoleController {

    @Autowired
    private RoleService roleService;

    /**
     * Obtiene la lista de todos los roles registrados.
     * 
     * @return Lista de objetos Role
     */
    @GetMapping
    public List<Role> find() {
        return this.roleService.find();
    }

    /**
     * Obtiene un rol específico por su identificador.
     * 
     * @param id Identificador único del rol (ObjectId de MongoDB)
     * @return Objeto Role o null si no existe
     */
    @GetMapping("/{id}")
    public Role findById(@PathVariable String id) {
        return this.roleService.findById(id);
    }

    /**
     * Crea un nuevo rol en el sistema.
     * 
     * @param newRole Objeto Role con nombre y descripción
     * @return Rol creado con su ID asignado
     */
    @PostMapping
    public Role create(@RequestBody Role newRole) {
        return this.roleService.create(newRole);
    }

    /**
     * Actualiza los datos de un rol existente.
     * 
     * @param id      Identificador único del rol
     * @param newRole Objeto Role con los datos actualizados
     * @return Rol actualizado
     */
    @PutMapping("/{id}")
    public Role update(@PathVariable String id, @RequestBody Role newRole) {
        return this.roleService.update(id, newRole);
    }

    /**
     * Elimina un rol del sistema.
     * 
     * PRECAUCIÓN: Eliminar un rol puede afectar a usuarios que lo tengan asignado.
     * 
     * @param id Identificador único del rol a eliminar
     */
    @DeleteMapping("/{id}")
    public void delete(@PathVariable String id) {
        this.roleService.delete(id);
    }
}