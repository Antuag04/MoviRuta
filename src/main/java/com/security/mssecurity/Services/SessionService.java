package com.security.mssecurity.Services;

import com.security.mssecurity.Models.Session;
import com.security.mssecurity.Models.User;
import com.security.mssecurity.Repositories.SessionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Servicio para gestión de sesiones de usuario en el sistema.
 * 
 * Este servicio proporciona operaciones CRUD básicas para sesiones,
 * así como métodos especializados para búsqueda y gestión de sesiones
 * activas de los usuarios.
 * 
 * Las sesiones representan tokens JWT activos en el sistema. Cada vez
 * que un usuario inicia sesión exitosamente (local o OAuth), se crea
 * un registro de sesión que permite:
 * 
 * - Rastrear sesiones activas por usuario
 * - Implementar "ver dispositivos conectados"
 * - Cerrar sesiones remotas ("cerrar sesión en todos los dispositivos")
 * - Invalidar tokens específicos sin afectar otros
 * - Auditar accesos y actividad del usuario
 * - Detectar accesos simultáneos sospechosos
 * 
 * IMPORTANTE: La creación de sesiones NO se hace manualmente a través
 * de este servicio. Las sesiones se crean automáticamente en:
 * - SecurityService.verify2FA() - después de autenticación 2FA exitosa
 * - GoogleOAuthService.processGoogleLogin() - después de login con Google
 * - GitHubOAuthService.processGitHubLogin() - después de login con GitHub
 * - MicrosoftOAuthService.processMicrosoftLogin() - después de login con Microsoft
 * 
 * Los métodos de este servicio son principalmente para consulta y eliminación.
 * 
 * @see Session
 * @see SessionRepository
 */
@Service
public class SessionService {

    @Autowired
    private SessionRepository sessionRepository;

    /**
     * Obtiene todas las sesiones registradas en el sistema.
     * 
     * NOTA: En producción, este método debería estar restringido
     * solo a administradores, ya que expone todas las sesiones de
     * todos los usuarios.
     * 
     * Caso de uso: Panel de administración para monitoreo de sesiones activas.
     * 
     * @return Lista con todas las sesiones del sistema
     */
    public List<Session> find() {
        return this.sessionRepository.findAll();
    }

    /**
     * Busca una sesión específica por su ID.
     * 
     * Útil para operaciones administrativas o cuando se necesita
     * verificar la existencia de una sesión específica antes de
     * realizar alguna acción sobre ella.
     * 
     * @param id Identificador único de la sesión (ObjectId de MongoDB)
     * @return Session si existe, null si no se encuentra
     */
    public Session findById(String id) {
        return this.sessionRepository.findById(id).orElse(null);
    }

    /**
     * Busca una sesión por su token JWT.
     * 
     * Este método es fundamental para:
     * - Implementar logout (cerrar sesión actual)
     * - Validar que un token JWT esté registrado en el sistema
     * - Verificar la expiración de una sesión
     * 
     * Flujo típico de logout:
     * ```java
     * String token = request.getHeader("Authorization").replace("Bearer ", "");
     * Session session = sessionService.findByToken(token);
     * if (session != null) {
     *     sessionService.delete(session.getId());
     *     return "Sesión cerrada exitosamente";
     * }
     * ```
     * 
     * @param token Token JWT a buscar (sin el prefijo "Bearer ")
     * @return Session si existe un registro con ese token, null si no existe
     */
    public Session findByToken(String token) {
        return sessionRepository.findByToken(token);
    }

    /**
     * Busca todas las sesiones activas de un usuario específico.
     * 
     * Un usuario puede tener múltiples sesiones activas simultáneamente
     * (una por cada dispositivo/navegador desde el que haya iniciado sesión).
     * 
     * Este método es la base para implementar:
     * - Página "Mis sesiones activas" en el perfil del usuario
     * - Mostrar lista de dispositivos conectados
     * - Detectar accesos simultáneos sospechosos
     * 
     * @param user Usuario propietario de las sesiones
     * @return Lista de sesiones activas del usuario (puede estar vacía si no hay sesiones)
     */
    public List<Session> findByUser(User user) {
        return sessionRepository.findByUser(user);
    }

    /**
     * Crea y persiste una nueva sesión en la base de datos.
     * 
     * IMPORTANTE: Este método NO debería usarse directamente.
     * Las sesiones se crean automáticamente en los servicios de autenticación.
     * 
     * @param newSession Objeto Session a crear
     * @return Session creada con su ID asignado por MongoDB
     */
    public Session create(Session newSession) {
        return this.sessionRepository.save(newSession);
    }

    /**
     * Actualiza una sesión existente.
     * 
     * NOTA: En la práctica, las sesiones raramente se actualizan.
     * Una vez creadas, generalmente se consultan o se eliminan.
     * 
     * @param id ID de la sesión a actualizar
     * @param newSession Objeto con los nuevos datos
     * @return Session actualizada si existe, null si no se encuentra
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
     * Elimina una sesión específica por su ID.
     * 
     * Este método se usa para:
     * - Cerrar una sesión específica (ej: "Cerrar sesión en mi iPhone")
     * - Limpieza de sesiones expiradas (job automático)
     * - Operaciones administrativas
     * 
     * @param id ID de la sesión a eliminar
     */
    public void delete(String id) {
        Session theSession = this.sessionRepository.findById(id).orElse(null);
        if (theSession != null) {
            this.sessionRepository.delete(theSession);
        }
    }

    /**
     * Elimina todas las sesiones de un usuario específico.
     * 
     * Este método implementa la funcionalidad crítica de seguridad:
     * "Cerrar sesión en todos los dispositivos"
     * 
     * Casos de uso:
     * 1. Usuario detecta acceso no autorizado
     * 2. Cambio de contraseña (invalidar sesiones anteriores)
     * 3. Usuario perdió un dispositivo
     * 
     * NOTA: Esta operación es permanente y no se puede deshacer.
     * El usuario deberá autenticarse nuevamente en todos sus dispositivos.
     * 
     * @param user Usuario cuyas sesiones serán eliminadas
     */
    public void deleteByUser(User user) {
        sessionRepository.deleteByUser(user);
    }
}
