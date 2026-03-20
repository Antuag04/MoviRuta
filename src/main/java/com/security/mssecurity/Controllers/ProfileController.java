package com.security.mssecurity.Controllers;

import com.security.mssecurity.Models.Profile;
import com.security.mssecurity.Services.ProfileService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Controlador REST para la gestión de perfiles de usuario.
 * 
 * Este controlador expone endpoints protegidos bajo /api/profiles que permiten
 * administrar la información adicional de los perfiles de usuario, como
 * teléfono y fotografía.
 * 
 * La asociación entre User y Profile se gestiona mediante los endpoints
 * del UserController.
 * 
 * @see ProfileService
 * @see com.security.mssecurity.Models.Profile
 */
@CrossOrigin
@RestController
@RequestMapping("/api/profiles")
public class ProfileController {

    @Autowired
    private ProfileService profileService;

    /**
     * Obtiene la lista de todos los perfiles registrados.
     * 
     * @return Lista de objetos Profile
     */
    @GetMapping
    public List<Profile> find() {
        return this.profileService.find();
    }

    /**
     * Obtiene un perfil específico por su identificador.
     * 
     * @param id Identificador único del perfil (ObjectId de MongoDB)
     * @return Objeto Profile o null si no existe
     */
    @GetMapping("/{id}")
    public Profile findById(@PathVariable String id) {
        return this.profileService.findById(id);
    }

    /**
     * Crea un nuevo perfil en el sistema.
     * 
     * @param newProfile Objeto Profile con teléfono y foto
     * @return Perfil creado con su ID asignado
     */
    @PostMapping
    public Profile create(@RequestBody Profile newProfile) {
        return this.profileService.create(newProfile);
    }

    /**
     * Actualiza los datos de un perfil existente.
     * 
     * @param id         Identificador único del perfil
     * @param newProfile Objeto Profile con los datos actualizados
     * @return Perfil actualizado
     */
    @PutMapping("/{id}")
    public Profile update(@PathVariable String id, @RequestBody Profile newProfile) {
        return this.profileService.update(id, newProfile);
    }

    /**
     * Elimina un perfil del sistema.
     * 
     * @param id Identificador único del perfil a eliminar
     */
    @DeleteMapping("/{id}")
    public void delete(@PathVariable String id) {
        this.profileService.delete(id);
    }
}
