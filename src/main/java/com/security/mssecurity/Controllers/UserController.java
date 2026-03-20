package com.security.mssecurity.Controllers;

import com.security.mssecurity.Models.User;
import com.security.mssecurity.Services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Controlador REST para la gestión de usuarios.
 * 
 * Este controlador expone endpoints protegidos bajo /api/users que requieren
 * autenticación mediante token JWT. Proporciona operaciones CRUD completas
 * para la entidad User, así como la gestión de relaciones con Profile y Session.
 * 
 * Los endpoints están protegidos por el SecurityInterceptor, que verifica
 * que el usuario tenga los permisos necesarios según su rol.
 * 
 * @see UserService
 * @see com.security.mssecurity.Interceptors.SecurityInterceptor
 */
@CrossOrigin
@RestController
@RequestMapping("/api/users")
public class UserController {

    @Autowired
    private UserService userService;

    /**
     * Obtiene la lista de todos los usuarios registrados.
     * 
     * @return Lista de objetos User
     */
    @GetMapping
    public List<User> find() {
        return userService.find();
    }

    /**
     * Obtiene un usuario específico por su identificador.
     * 
     * @param id Identificador único del usuario (ObjectId de MongoDB)
     * @return Objeto User o null si no existe
     */
    @GetMapping("{id}")
    public User findById(@PathVariable String id) {
        return userService.findById(id);
    }

    /**
     * Crea un nuevo usuario en el sistema.
     * 
     * NOTA: Para registro de usuarios nuevos con validaciones completas,
     * utilizar el endpoint /api/public/security/register
     * 
     * @param usuario Objeto User con los datos del nuevo usuario
     * @return Usuario creado con su ID asignado
     */
    @PostMapping
    public User create(@RequestBody User usuario) {
        return userService.create(usuario);
    }

    /**
     * Actualiza los datos de un usuario existente.
     * 
     * @param id      Identificador único del usuario
     * @param usuario Objeto User con los datos actualizados
     * @return Usuario actualizado
     */
    @PutMapping("{id}")
    public User update(@PathVariable String id, @RequestBody User usuario) {
        return userService.update(id, usuario);
    }

    /**
     * Elimina un usuario del sistema.
     * 
     * @param id Identificador único del usuario a eliminar
     */
    @DeleteMapping("{id}")
    public void delete(@PathVariable String id) {
        userService.delete(id);
    }

    /**
     * Asocia un perfil existente a un usuario.
     * 
     * Establece la relación entre User y Profile. Ambas entidades
     * deben existir previamente en la base de datos.
     * 
     * @param userId    Identificador del usuario
     * @param profileId Identificador del perfil a asociar
     * @return ResponseEntity con mensaje de éxito o error
     */
    @PostMapping("{userId}/profile/{profileId}")
    public ResponseEntity<Map<String, String>> addUserProfile(
            @PathVariable String userId,
            @PathVariable String profileId) {

        boolean response = this.userService.addProfile(userId, profileId);
        if (response) {
            return ResponseEntity.ok(Map.of("message", "Success"));
        } else {
            return ResponseEntity
                    .status(HttpStatus.NOT_FOUND)
                    .body(Map.of("message", "User or Profile not found"));
        }
    }

    /**
     * Elimina la asociación entre un usuario y su perfil.
     * 
     * @param userId    Identificador del usuario
     * @param profileId Identificador del perfil a desasociar
     * @return ResponseEntity con mensaje de éxito o error
     */
    @DeleteMapping("{userId}/profile/{profileId}")
    public ResponseEntity<Map<String, String>> deleteUserProfile(
            @PathVariable String userId,
            @PathVariable String profileId) {

        boolean response = this.userService.removeProfile(userId, profileId);
        if (response) {
            return ResponseEntity.ok(Map.of("message", "Success"));
        } else {
            return ResponseEntity
                    .status(HttpStatus.NOT_FOUND)
                    .body(Map.of("message", "User or Profile not found"));
        }
    }

    /**
     * Asocia una sesión existente a un usuario.
     * 
     * @param userId    Identificador del usuario
     * @param sessionId Identificador de la sesión a asociar
     * @return ResponseEntity con mensaje de éxito o error
     */
    @PostMapping("{userId}/session/{sessionId}")
    public ResponseEntity<Map<String, String>> addUserSession(
            @PathVariable String userId,
            @PathVariable String sessionId) {

        boolean response = this.userService.addSession(userId, sessionId);
        if (response) {
            return ResponseEntity.ok(Map.of("message", "Success"));
        } else {
            return ResponseEntity
                    .status(HttpStatus.NOT_FOUND)
                    .body(Map.of("message", "User or Session not found"));
        }
    }

    /**
     * Elimina la asociación entre un usuario y una sesión.
     * 
     * @param userId    Identificador del usuario
     * @param sessionId Identificador de la sesión a desasociar
     * @return ResponseEntity con mensaje de éxito o error
     */
    @DeleteMapping("{userId}/session/{sessionId}")
    public ResponseEntity<Map<String, String>> deleteUserSession(
            @PathVariable String userId,
            @PathVariable String sessionId) {

        boolean response = this.userService.removeSession(userId, sessionId);
        if (response) {
            return ResponseEntity.ok(Map.of("message", "Success"));
        } else {
            return ResponseEntity
                    .status(HttpStatus.NOT_FOUND)
                    .body(Map.of("message", "User or Session not found"));
        }
    }
}