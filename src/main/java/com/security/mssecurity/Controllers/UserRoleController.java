package com.security.mssecurity.Controllers;

import com.security.mssecurity.Services.UserRoleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Controlador REST para la gestión de asignaciones usuario-rol.
 * 
 * Este controlador expone endpoints protegidos bajo /api/user-role que permiten
 * asignar y revocar roles a usuarios, gestionando la relación muchos-a-muchos
 * entre las entidades User y Role.
 * 
 * La asignación de roles determina qué permisos tiene cada usuario en el sistema,
 * siguiendo el modelo de control de acceso basado en roles (RBAC).
 * 
 * NOTA: Al registrarse, los usuarios reciben automáticamente el rol "CIUDADANO".
 * Los roles adicionales deben asignarse mediante estos endpoints.
 * 
 * @see UserRoleService
 * @see com.security.mssecurity.Models.UserRole
 */
@CrossOrigin
@RestController
@RequestMapping("/api/user-role")
public class UserRoleController {

    @Autowired
    private UserRoleService theUserRoleService;

    /**
     * Asigna un rol a un usuario.
     * 
     * Crea una nueva relación UserRole entre el usuario y el rol especificados.
     * Ambas entidades deben existir previamente en la base de datos.
     * 
     * @param userId Identificador único del usuario
     * @param roleId Identificador único del rol a asignar
     * @return ResponseEntity con mensaje de éxito o error si no se encuentran las entidades
     */
    @PostMapping("user/{userId}/role/{roleId}")
    public ResponseEntity<Map<String, String>> addUserRole(
            @PathVariable String userId,
            @PathVariable String roleId) {

        boolean response = this.theUserRoleService.addUserRole(userId, roleId);
        if (response) {
            return ResponseEntity.ok(Map.of("message", "Success"));
        } else {
            return ResponseEntity
                    .status(HttpStatus.NOT_FOUND)
                    .body(Map.of("message", "User or Role not found"));
        }
    }

    /**
     * Elimina una asignación usuario-rol.
     * 
     * Revoca el rol del usuario eliminando el registro UserRole correspondiente.
     * Esto afecta inmediatamente los permisos del usuario.
     * 
     * @param userRoleId Identificador único de la asignación UserRole
     * @return ResponseEntity con mensaje de éxito o error si no se encuentra la asignación
     */
    @DeleteMapping("{userRoleId}")
    public ResponseEntity<Map<String, String>> removeUserRole(
            @PathVariable String userRoleId) {

        boolean response = this.theUserRoleService.removeUserRole(userRoleId);
        if (response) {
            return ResponseEntity.ok(Map.of("message", "Success"));
        } else {
            return ResponseEntity
                    .status(HttpStatus.NOT_FOUND)
                    .body(Map.of("message", "User or Role not found"));
        }
    }
}
