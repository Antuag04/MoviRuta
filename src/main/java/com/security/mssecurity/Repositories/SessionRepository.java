package com.security.mssecurity.Repositories;

import com.security.mssecurity.Models.Session;
import com.security.mssecurity.Models.User;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * Repositorio para acceso a datos de la colección de sesiones en MongoDB.
 * 
 * Proporciona operaciones CRUD básicas para la gestión de sesiones
 * de usuario en el sistema, así como consultas especializadas para
 * búsqueda y gestión de sesiones activas.
 * 
 * Las sesiones representan tokens JWT activos en el sistema. Cada vez
 * que un usuario inicia sesión (local o OAuth), se crea un registro
 * de sesión que permite:
 * - Rastrear sesiones activas por usuario
 * - Implementar "cerrar sesión en todos los dispositivos"
 * - Invalidar tokens específicos
 * - Auditar accesos al sistema
 * 
 * @see Session
 * @see User
 */
@Repository
public interface SessionRepository extends MongoRepository<Session, String> {
    
    /**
     * Busca una sesión activa por su token JWT.
     * 
     * Este método es útil para:
     * - Validar si un token está activo en el sistema
     * - Implementar logout (eliminar sesión por token)
     * - Verificar la existencia de una sesión antes de operaciones sensibles
     * 
     * Ejemplo de uso:
     * ```java
     * String jwtToken = "eyJhbGciOiJIUzUxMiJ9...";
     * Session session = sessionRepository.findByToken(jwtToken);
     * if (session != null && !session.getExpiration().before(new Date())) {
     *     // Token válido y no expirado
     * }
     * ```
     * 
     * @param token Token JWT de la sesión a buscar
     * @return Session si existe una sesión con ese token, null si no existe
     */
    Session findByToken(String token);
    
    /**
     * Busca todas las sesiones activas de un usuario específico.
     * 
     * Un usuario puede tener múltiples sesiones activas simultáneamente
     * (una por cada dispositivo/navegador desde el que haya iniciado sesión).
     * 
     * Este método es útil para:
     * - Mostrar al usuario sus sesiones activas en diferentes dispositivos
     * - Implementar una página de "gestión de sesiones"
     * - Detectar posibles accesos no autorizados
     * - Auditar la actividad del usuario
     * 
     * Relación: User (1) → Session (N)
     * Un usuario puede tener muchas sesiones, pero cada sesión pertenece a un solo usuario.
     * 
     * Ejemplo de uso:
     * ```java
     * User currentUser = getUserFromToken(jwt);
     * List<Session> activeSessions = sessionRepository.findByUser(currentUser);
     * // Retorna todas las sesiones del usuario (móvil, desktop, tablet, etc.)
     * ```
     * 
     * @param user Usuario propietario de las sesiones
     * @return Lista de sesiones activas del usuario (puede estar vacía si no hay sesiones)
     */
    List<Session> findByUser(User user);
    
    /**
     * Elimina todas las sesiones de un usuario específico.
     * 
     * Esta operación implementa la funcionalidad "cerrar sesión en todos
     * los dispositivos". Es útil en casos de seguridad como:
     * - Usuario detecta acceso no autorizado
     * - Cambio de contraseña (invalidar todas las sesiones anteriores)
     * - Usuario perdió un dispositivo
     * - Administrador necesita forzar re-autenticación
     * 
     * Al eliminar todas las sesiones, todos los tokens JWT del usuario
     * quedan invalidados (si implementas validación contra la base de datos).
     * 
     * IMPORTANTE: Esta operación es permanente y no se puede deshacer.
     * El usuario deberá iniciar sesión nuevamente en todos sus dispositivos.
     * 
     * Ejemplo de uso:
     * ```java
     * User currentUser = getUserFromToken(jwt);
     * sessionRepository.deleteByUser(currentUser);
     * // Ahora el usuario debe volver a hacer login en todos sus dispositivos
     * ```
     * 
     * @param user Usuario cuyas sesiones serán eliminadas
     */
    void deleteByUser(User user);
}
