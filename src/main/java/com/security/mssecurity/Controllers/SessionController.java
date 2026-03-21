package com.security.mssecurity.Controllers;

import com.security.mssecurity.Models.Session;
import com.security.mssecurity.Models.User;
import com.security.mssecurity.Services.JwtService;
import com.security.mssecurity.Services.SessionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Controlador REST para la gestión de sesiones de usuario.
 * 
 * Este controlador expone endpoints protegidos bajo /api/sessions que permiten
 * administrar las sesiones activas de los usuarios, incluyendo operaciones
 * CRUD completas para la entidad Session, así como endpoints especializados
 * para gestión de sesiones del usuario autenticado.
 * 
 * ENDPOINTS PRINCIPALES:
 * 
 * 1. Endpoints CRUD tradicionales (administrativos):
 *    - GET    /api/sessions           - Listar todas las sesiones (admin)
 *    - GET    /api/sessions/{id}      - Obtener sesión por ID
 *    - POST   /api/sessions           - Crear sesión manualmente
 *    - PUT    /api/sessions/{id}      - Actualizar sesión
 *    - DELETE /api/sessions/{id}      - Eliminar sesión por ID
 * 
 * 2. Endpoints para usuario autenticado (nuevos):
 *    - GET    /api/sessions/my-sessions     - Ver mis sesiones activas
 *    - DELETE /api/sessions/logout          - Cerrar sesión actual
 *    - DELETE /api/sessions/logout-all      - Cerrar todas mis sesiones
 *    - DELETE /api/sessions/close/{id}      - Cerrar sesión específica mía
 * 
 * SEGURIDAD:
 * - Todos los endpoints requieren JWT válido (excepto los públicos)
 * - Los endpoints "my-*" solo operan sobre sesiones del usuario autenticado
 * - No se puede cerrar sesión de otro usuario sin permisos de admin
 * 
 * Las sesiones se crean automáticamente en:
 * - Login local exitoso (después de 2FA)
 * - Login OAuth exitoso (Google, GitHub, Microsoft)
 * 
 * @see SessionService
 * @see Session
 * @see JwtService
 */
@CrossOrigin
@RestController
@RequestMapping("/api/sessions")
public class SessionController {

    @Autowired
    private SessionService sessionService;

    @Autowired
    private JwtService jwtService;

    /**
     * Obtiene la lista de todas las sesiones registradas en el sistema.
     * 
     * IMPORTANTE: Este endpoint debería estar protegido con permisos
     * de administrador, ya que expone información sensible de todos
     * los usuarios del sistema.
     * 
     * Caso de uso: Panel de administración para monitoreo de sesiones activas.
     * 
     * @return Lista con todas las sesiones del sistema
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
     * Crea una nueva sesión manualmente en el sistema.
     * 
     * NOTA: En el flujo normal, las sesiones se crean automáticamente
     * al hacer login. Este endpoint es principalmente para operaciones
     * administrativas o de testing.
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
     * NOTA: Las sesiones raramente se actualizan. Este endpoint
     * está disponible para casos especiales o administrativos.
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
     * Elimina una sesión específica del sistema por su ID.
     * 
     * @param id Identificador único de la sesión a eliminar
     */
    @DeleteMapping("/{id}")
    public void delete(@PathVariable String id) {
        this.sessionService.delete(id);
    }

    /**
     * Obtiene todas las sesiones activas del usuario autenticado.
     * 
     * Este endpoint permite al usuario ver en qué dispositivos/navegadores
     * tiene sesiones activas actualmente. Es la base para implementar
     * una página de "Gestión de dispositivos conectados" en el frontend.
     * 
     * FLUJO:
     * 1. Frontend envía petición con JWT en header Authorization
     * 2. Backend extrae el token y obtiene el usuario del JWT
     * 3. Backend busca todas las sesiones de ese usuario
     * 4. Frontend muestra lista de sesiones al usuario
     * 
     * Ejemplo de respuesta:
     * ```json
     * [
     *   {
     *     "id": "65a1b2c3...",
     *     "token": "eyJhbGci...",
     *     "expiration": "2024-01-15T11:00:00Z",
     *     "user": { "id": "65a1...", "name": "Juan Pérez" }
     *   },
     *   {
     *     "id": "65a1b2c4...",
     *     "token": "eyJhbGci...",
     *     "expiration": "2024-01-15T12:00:00Z",
     *     "user": { "id": "65a1...", "name": "Juan Pérez" }
     *   }
     * ]
     * ```
     * 
     * El frontend puede mejorar la visualización agregando:
     * - Detección de dispositivo por User-Agent (mostrar "iPhone", "Chrome en Windows", etc.)
     * - Indicador de sesión actual (la que está usando ahora)
     * - Última actividad de cada sesión
     * - Ubicación aproximada por IP (requiere servicio de geolocalización)
     * 
     * Mejora futura: Agregar campos a Session para guardar:
     * - ipAddress: String
     * - userAgent: String  
     * - lastActivity: Date
     * - location: String
     * 
     * @param authHeader Header Authorization con formato "Bearer {token}"
     * @return ResponseEntity con lista de sesiones o código de error
     */
    @GetMapping("/my-sessions")
    public ResponseEntity<?> getMyActiveSessions(@RequestHeader("Authorization") String authHeader) {
        try {
            // Extraer el token JWT del header (remover prefijo "Bearer ")
            String token = authHeader.replace("Bearer ", "");
            
            // Obtener el usuario desde el token JWT
            User user = jwtService.getUserFromToken(token);
            
            // Validar que el token sea válido y tenga usuario
            if (user == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Token inválido o expirado"));
            }
            
            // Buscar todas las sesiones del usuario
            List<Session> sessions = sessionService.findByUser(user);
            
            return ResponseEntity.ok(sessions);
            
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "Error al obtener sesiones: " + e.getMessage()));
        }
    }

    /**
     * Cierra la sesión actual del usuario autenticado.
     * 
     * Este endpoint implementa el logout tradicional: cierra solo la sesión
     * desde la que se hace la petición, dejando activas las sesiones en
     * otros dispositivos.
     * 
     * FLUJO:
     * 1. Usuario hace click en "Cerrar sesión" en el frontend
     * 2. Frontend envía petición DELETE con el JWT en el header
     * 3. Backend busca la sesión por el token
     * 4. Backend elimina la sesión de la base de datos
     * 5. Frontend elimina el token del localStorage/sessionStorage
     * 6. Frontend redirige a página de login
     * 
     * Ejemplo de uso desde frontend:
     * ```javascript
     * const logout = async () => {
     *   const token = localStorage.getItem('jwt');
     *   await fetch('/api/sessions/logout', {
     *     method: 'DELETE',
     *     headers: { 'Authorization': `Bearer ${token}` }
     *   });
     *   localStorage.removeItem('jwt');
     *   window.location.href = '/login';
     * };
     * ```
     * 
     * IMPORTANTE: Eliminar la sesión de la BD NO invalida el JWT automáticamente.
     * El JWT seguirá siendo técnicamente válido hasta su expiración natural.
     * Sin embargo, si implementas un middleware que verifica la existencia de
     * la sesión en BD antes de permitir el acceso, el token quedará invalidado.
     * 
     * @param authHeader Header Authorization con formato "Bearer {token}"
     * @return ResponseEntity con mensaje de éxito o código de error
     */
    @DeleteMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader("Authorization") String authHeader) {
        try {
            // Extraer el token JWT del header
            String token = authHeader.replace("Bearer ", "");
            
            // Buscar la sesión por el token
            Session session = sessionService.findByToken(token);
            
            if (session != null) {
                // Eliminar la sesión de la base de datos
                sessionService.delete(session.getId());
                
                return ResponseEntity.ok(Map.of(
                    "message", "Sesión cerrada exitosamente"
                ));
            }
            
            // Token no encontrado en sesiones (ya fue eliminado o nunca existió)
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(Map.of("error", "Sesión no encontrada"));
                
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "Error al cerrar sesión: " + e.getMessage()));
        }
    }

    /**
     * Cierra todas las sesiones del usuario autenticado.
     * 
     * Este endpoint implementa la funcionalidad crítica de seguridad
     * "Cerrar sesión en todos los dispositivos". Es especialmente útil en
     * situaciones de seguridad como:
     * 
     * - Usuario detecta acceso no autorizado o sospechoso
     * - Usuario cambia su contraseña y quiere invalidar sesiones antiguas
     * - Usuario perdió un dispositivo (teléfono, tablet, etc.)
     * - Como medida preventiva después de usar un computador público
     * 
     * FLUJO:
     * 1. Usuario hace click en "Cerrar sesión en todos los dispositivos"
     * 2. Frontend envía petición DELETE /logout-all con JWT
     * 3. Backend obtiene el usuario del JWT
     * 4. Backend elimina TODAS las sesiones de ese usuario
     * 5. Frontend elimina su token local y redirige a login
     * 6. Otros dispositivos intentan hacer peticiones → reciben 401 Unauthorized
     * 7. Otros dispositivos deben volver a hacer login
     * 
     * Ejemplo de uso desde frontend:
     * ```javascript
     * const logoutAllDevices = async () => {
     *   if (confirm('¿Cerrar sesión en todos los dispositivos?')) {
     *     const token = localStorage.getItem('jwt');
     *     await fetch('/api/sessions/logout-all', {
     *       method: 'DELETE',
     *       headers: { 'Authorization': `Bearer ${token}` }
     *     });
     *     localStorage.removeItem('jwt');
     *     alert('Sesiones cerradas. Deberás volver a iniciar sesión en todos tus dispositivos.');
     *     window.location.href = '/login';
     *   }
     * };
     * ```
     * 
     * ADVERTENCIA: Esta operación es permanente y no se puede deshacer.
     * El usuario deberá autenticarse nuevamente en TODOS sus dispositivos,
     * incluyendo el dispositivo desde el que hace la petición.
     * 
     * Caso de uso real:
     * "Inicié sesión en el computador de un amigo y olvidé cerrar sesión.
     *  Desde mi teléfono voy a Configuración → Seguridad → Cerrar todas las sesiones.
     *  Ahora mi amigo no puede acceder a mi cuenta desde su computador."
     * 
     * @param authHeader Header Authorization con formato "Bearer {token}"
     * @return ResponseEntity con mensaje de éxito o código de error
     */
    @DeleteMapping("/logout-all")
    public ResponseEntity<?> logoutAll(@RequestHeader("Authorization") String authHeader) {
        try {
            // Extraer el token JWT del header
            String token = authHeader.replace("Bearer ", "");
            
            // Obtener el usuario desde el token JWT
            User user = jwtService.getUserFromToken(token);
            
            // Validar que el token sea válido y tenga usuario
            if (user == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Token inválido o expirado"));
            }
            
            // Eliminar TODAS las sesiones del usuario
            sessionService.deleteByUser(user);
            
            return ResponseEntity.ok(Map.of(
                "message", "Todas las sesiones han sido cerradas. Deberás iniciar sesión nuevamente en todos tus dispositivos."
            ));
            
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "Error al cerrar sesiones: " + e.getMessage()));
        }
    }

    /**
     * Cierra una sesión específica del usuario autenticado.
     * 
     * Este endpoint permite al usuario cerrar una sesión particular desde
     * su página de gestión de dispositivos, sin afectar sus otras sesiones.
     * Es útil cuando el usuario puede identificar qué sesión corresponde a
     * qué dispositivo y solo quiere cerrar una en específico.
     * 
     * FLUJO:
     * 1. Usuario va a "Mis dispositivos" y ve lista de sesiones
     * 2. Identifica sesión sospechosa o de dispositivo que ya no usa
     * 3. Hace click en "Cerrar sesión" junto a esa sesión específica
     * 4. Frontend envía DELETE /close/{sessionId}
     * 5. Backend verifica que la sesión pertenezca al usuario
     * 6. Backend elimina solo esa sesión
     * 7. Las demás sesiones del usuario siguen activas
     * 
     * SEGURIDAD: El backend verifica que la sesión a cerrar pertenezca
     * al usuario autenticado. No se puede cerrar sesión de otro usuario.
     * 
     * Ejemplo de UI en frontend:
     * ```
     * Mis dispositivos conectados:
     * 
     * 📱 iPhone 13 Pro
     *    Último acceso: hace 2 horas
     *    Ubicación: Bogotá, Colombia
     *    [Cerrar sesión] ← llama a este endpoint
     * 
     * 💻 Chrome en Windows
     *    Último acceso: hace 1 día
     *    Ubicación: Medellín, Colombia
     *    [Cerrar sesión]
     * 
     * 📱 iPad Air
     *    Último acceso: hace 3 días
     *    Ubicación: Cali, Colombia
     *    [Cerrar sesión]
     * ```
     * 
     * Ejemplo de uso desde frontend:
     * ```javascript
     * const closeSession = async (sessionId) => {
     *   const token = localStorage.getItem('jwt');
     *   await fetch(`/api/sessions/close/${sessionId}`, {
     *     method: 'DELETE',
     *     headers: { 'Authorization': `Bearer ${token}` }
     *   });
     *   alert('Sesión cerrada');
     *   // Recargar lista de sesiones
     *   loadMySessions();
     * };
     * ```
     * 
     * @param sessionId ID de la sesión específica a cerrar
     * @param authHeader Header Authorization con formato "Bearer {token}"
     * @return ResponseEntity con mensaje de éxito o código de error
     */
    @DeleteMapping("/close/{sessionId}")
    public ResponseEntity<?> closeSpecificSession(
            @PathVariable String sessionId,
            @RequestHeader("Authorization") String authHeader) {
        try {
            // Extraer el token JWT del header
            String token = authHeader.replace("Bearer ", "");
            
            // Obtener el usuario desde el token JWT
            User user = jwtService.getUserFromToken(token);
            
            // Validar que el token sea válido y tenga usuario
            if (user == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Token inválido o expirado"));
            }
            
            // Buscar la sesión específica
            Session session = sessionService.findById(sessionId);
            
            if (session == null) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("error", "Sesión no encontrada"));
            }
            
            // SEGURIDAD: Verificar que la sesión pertenezca al usuario autenticado
            // No se puede cerrar sesión de otro usuario
            if (!session.getUser().getId().equals(user.getId())) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("error", "No tienes permiso para cerrar esta sesión"));
            }
            
            // Eliminar la sesión
            sessionService.delete(sessionId);
            
            return ResponseEntity.ok(Map.of(
                "message", "Sesión cerrada exitosamente"
            ));
            
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "Error al cerrar sesión: " + e.getMessage()));
        }
    }
}
