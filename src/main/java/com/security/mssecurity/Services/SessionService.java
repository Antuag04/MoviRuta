package com.security.mssecurity.Services;

import com.security.mssecurity.Models.Session;
import com.security.mssecurity.Repositories.SessionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Servicio que gestiona las operaciones CRUD de sesiones.
 * 
 * Las sesiones almacenan información sobre los tokens JWT emitidos,
 * permitiendo el seguimiento de sesiones activas y la implementación
 * de funcionalidades como cierre de sesión o invalidación de tokens.
 * 
 * @see SessionRepository
 * @see com.security.mssecurity.Models.Session
 */
@Service
public class SessionService {

    @Autowired
    private SessionRepository sessionRepository;

    /**
     * Obtiene la lista de todas las sesiones.
     * 
     * @return Lista de sesiones
     */
    public List<Session> find() {
        return this.sessionRepository.findAll();
    }

    /**
     * Busca una sesión por su identificador.
     * 
     * @param id Identificador único de la sesión
     * @return Sesión encontrada o null si no existe
     */
    public Session findById(String id) {
        return this.sessionRepository.findById(id).orElse(null);
    }

    /**
     * Crea una nueva sesión.
     * 
     * @param newSession Datos de la nueva sesión
     * @return Sesión creada con su ID asignado
     */
    public Session create(Session newSession) {
        return this.sessionRepository.save(newSession);
    }

    /**
     * Actualiza una sesión existente.
     * 
     * @param id         Identificador de la sesión a actualizar
     * @param newSession Datos actualizados
     * @return Sesión actualizada o null si no existe
     */
    public Session update(String id, Session newSession) {
        Session actualSession = this.sessionRepository.findById(id).orElse(null);

        if (actualSession != null) {
            actualSession.setToken(newSession.getToken());
            actualSession.setExpiration(newSession.getExpiration());
            actualSession.setCode2FA(newSession.getCode2FA());
            this.sessionRepository.save(actualSession);
            return actualSession;
        } else {
            return null;
        }
    }

    /**
     * Elimina una sesión del sistema.
     * 
     * @param id Identificador de la sesión a eliminar
     */
    public void delete(String id) {
        Session theSession = this.sessionRepository.findById(id).orElse(null);
        if (theSession != null) {
            this.sessionRepository.delete(theSession);
        }
    }
}
