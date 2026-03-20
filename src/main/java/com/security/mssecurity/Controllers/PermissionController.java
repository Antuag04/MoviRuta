package com.security.mssecurity.Controllers;

import com.security.mssecurity.Models.Permission;
import com.security.mssecurity.Services.PermissionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Controlador REST para la gestión de permisos del sistema.
 * 
 * Este controlador expone endpoints protegidos bajo /api/permissions que permiten
 * administrar los permisos utilizados en el sistema de control de acceso.
 * 
 * Cada permiso define una combinación de URL y método HTTP que representa
 * un recurso protegido del sistema. Los permisos se asignan a roles mediante
 * la entidad RolePermission.
 * 
 * @see PermissionService
 * @see com.security.mssecurity.Models.Permission
 */
@CrossOrigin
@RestController
@RequestMapping("/api/permissions")
public class PermissionController {

    @Autowired
    private PermissionService permissionService;

    /**
     * Obtiene la lista de todos los permisos registrados.
     * 
     * @return Lista de objetos Permission
     */
    @GetMapping
    public List<Permission> find() {
        return this.permissionService.find();
    }

    /**
     * Obtiene un permiso específico por su identificador.
     * 
     * @param id Identificador único del permiso (ObjectId de MongoDB)
     * @return Objeto Permission o null si no existe
     */
    @GetMapping("/{id}")
    public Permission findById(@PathVariable String id) {
        return this.permissionService.findById(id);
    }

    /**
     * Crea un nuevo permiso en el sistema.
     * 
     * Campos requeridos:
     * - url: Ruta del endpoint (ej: "/api/users/?")
     * - method: Método HTTP (GET, POST, PUT, DELETE)
     * - model: Nombre de la entidad relacionada (ej: "User")
     * 
     * @param newPermission Objeto Permission con los datos del nuevo permiso
     * @return Permiso creado con su ID asignado
     */
    @PostMapping
    public Permission create(@RequestBody Permission newPermission) {
        return this.permissionService.create(newPermission);
    }

    /**
     * Actualiza los datos de un permiso existente.
     * 
     * @param id            Identificador único del permiso
     * @param newPermission Objeto Permission con los datos actualizados
     * @return Permiso actualizado
     */
    @PutMapping("/{id}")
    public Permission update(@PathVariable String id, @RequestBody Permission newPermission) {
        return this.permissionService.update(id, newPermission);
    }

    /**
     * Elimina un permiso del sistema.
     * 
     * PRECAUCIÓN: Eliminar un permiso puede afectar las asignaciones
     * rol-permiso existentes.
     * 
     * @param id Identificador único del permiso a eliminar
     */
    @DeleteMapping("/{id}")
    public void delete(@PathVariable String id) {
        this.permissionService.delete(id);
    }
}