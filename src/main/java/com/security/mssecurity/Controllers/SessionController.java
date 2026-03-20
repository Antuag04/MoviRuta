package com.security.mssecurity.Controllers;

import com.security.mssecurity.Models.Session;
import com.security.mssecurity.Services.SessionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Controlador REST para la gestión de sesiones de usuario.
 * 
 * Este controlador expone endpoints protegidos bajo /api/sessions que permiten
 * administrar las sesiones activas de los usuarios, incluyendo operaciones
 * CRUD completas para la entidad Session.
 * 
 * Las sesiones almacenan información sobre los tokens JWT emitidos,
 * su fecha de expiración y opcionalmente códigos de autenticación de dos factores.
 * 
 * @see SessionService
 * @see com.security.mssecurity.Models.Session
 */
@CrossOrigin
@RestController
@RequestMapping("/api/sessions")
public class SessionController {

    @Autowired
    private SessionService sessionService;

    /**
     * Obtiene la lista de todas las sesiones registradas.
     * 
     * @return Lista de objetos Session
     */
    @GetMapping
    public List<Session> find() {
        return this.sessionService.find();
    }

    /**
     * Obtiene una sesión específica por su identificador.
     * 
     * @param id Identificador único de la sesión (ObjectId de MongoDB)
     * @return Objeto Session o null si no existe
     */
    @GetMapping("/{id}")
    public Session findById(@PathVariable String id) {
        return this.sessionService.findById(id);
    }

    /**
     * Crea una nueva sesión en el sistema.
     * 
     * @param newSession Objeto Session con los datos de la nueva sesión
     * @return Sesión creada con su ID asignado
     */
    @PostMapping
    public Session create(@RequestBody Session newSession) {
        return this.sessionService.create(newSession);
    }

    /**
     * Actualiza los datos de una sesión existente.
     * 
     * @param id         Identificador único de la sesión
     * @param newSession Objeto Session con los datos actualizados
     * @return Sesión actualizada
     */
    @PutMapping("/{id}")
    public Session update(@PathVariable String id, @RequestBody Session newSession) {
        return this.sessionService.update(id, newSession);
    }

    /**
     * Elimina una sesión del sistema.
     * 
     * @param id Identificador único de la sesión a eliminar
     */
    @DeleteMapping("/{id}")
    public void delete(@PathVariable String id) {
        this.sessionService.delete(id);
    }
}
