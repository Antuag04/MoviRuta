package com.security.mssecurity.Controllers;

import com.security.mssecurity.Models.Profile;
import com.security.mssecurity.Models.User;
import com.security.mssecurity.Repositories.ProfileRepository;
import com.security.mssecurity.Services.JwtService;
import com.security.mssecurity.Services.ProfileService;
import com.security.mssecurity.Services.SecurityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Controlador REST para la gestión de perfiles de usuario.
 * 
 * Este controlador expone endpoints protegidos bajo /api/profiles que permiten
 * administrar la información adicional de los perfiles de usuario, como
 * teléfono y fotografía.
 * 
 * ENDPOINTS PRINCIPALES:
 * 
 * 1. Endpoints CRUD tradicionales (administrativos):
 *    - GET    /api/profiles          - Listar todos los perfiles (admin)
 *    - GET    /api/profiles/{id}     - Obtener perfil por ID
 *    - POST   /api/profiles          - Crear perfil manualmente
 *    - PUT    /api/profiles/{id}     - Actualizar perfil
 *    - DELETE /api/profiles/{id}     - Eliminar perfil
 * 
 * 2. Endpoint para usuario autenticado (nuevo):
 *    - GET    /api/profiles/me       - Obtener mi perfil
 * 
 * IMPORTANTE: Los perfiles se crean automáticamente al registrarse o
 * hacer primer login OAuth, por lo que el usuario siempre tiene perfil.
 * 
 * La asociación entre User y Profile se gestiona mediante los endpoints
 * del UserController o automáticamente en los servicios de autenticación.
 * 
 * @see ProfileService
 * @see Profile
 * @see JwtService
 */
@CrossOrigin
@RestController
@RequestMapping("/api/profiles")
public class ProfileController {

    @Autowired
    private ProfileService profileService;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private ProfileRepository profileRepository;

    @Autowired
    private SecurityService securityService;

    /**
     * Obtiene la lista de todos los perfiles registrados.
     * 
     * IMPORTANTE: Este endpoint debería estar protegido con permisos
     * de administrador, ya que expone información de todos los usuarios.
     * 
     * @return Lista con todos los perfiles del sistema
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
     * Crea un nuevo perfil manualmente en el sistema.
     * 
     * NOTA: En el flujo normal, los perfiles se crean automáticamente
     * al registrarse o hacer primer login OAuth. Este endpoint es
     * principalmente para operaciones administrativas o de testing.
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
     * Este endpoint permite actualizar teléfono y/o foto de perfil.
     * Es el que usa el usuario para completar o modificar su información.
     * 
     * Ejemplo de uso:
     * ```
     * PUT /api/profiles/65a1b2c3d4e5f6g7h8i9j0k2
     * {
     *   "phone": "+57 300 123 4567",
     *   "photo": "https://mi-servidor.com/uploads/mi-foto.jpg"
     * }
     * ```
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
     * ADVERTENCIA: Eliminar el perfil NO elimina el usuario.
     * Si se elimina el perfil, el usuario quedará sin perfil asociado.
     * 
     * @param id Identificador único del perfil a eliminar
     */
    @DeleteMapping("/{id}")
    public void delete(@PathVariable String id) {
        this.profileService.delete(id);
    }

    /**
     * Obtiene el perfil del usuario autenticado actual.
     * 
     * Este es el endpoint más importante para el frontend, ya que permite
     * obtener el perfil del usuario logueado sin necesidad de conocer el
     * ID del perfil de antemano.
     * 
     * FLUJO:
     * 1. Usuario navega a su página de perfil
     * 2. Frontend envía petición GET /api/profiles/me con JWT
     * 3. Backend extrae el usuario del JWT
     * 4. Backend busca el perfil asociado a ese usuario
     * 5. Backend retorna el perfil con phone y photo
     * 6. Frontend muestra los datos en la página de perfil
     * 
     * Ejemplo de uso desde frontend:
     * ```javascript
     * const getMyProfile = async () => {
     *   const token = localStorage.getItem('jwt');
     *   const response = await fetch('/api/profiles/me', {
     *     headers: { 'Authorization': `Bearer ${token}` }
     *   });
     *   const profile = await response.json();
     *   
     *   // Mostrar en UI
     *   document.getElementById('phone').value = profile.phone || '';
     *   document.getElementById('photo').src = profile.photo || 'default-avatar.png';
     * };
     * ```
     * 
     * Ejemplo de respuesta exitosa:
     * ```json
     * {
     *   "id": "65a1b2c3d4e5f6g7h8i9j0k2",
     *   "phone": "+57 300 123 4567",
     *   "photo": "https://lh3.googleusercontent.com/...",
     *   "user": {
     *     "id": "65a1b2c3d4e5f6g7h8i9j0k1",
     *     "name": "Juan Pérez",
     *     "email": "juan@gmail.com"
     *   }
     * }
     * ```
     * 
     * Caso de uso 1: Completar perfil después de registro local
     * ```
     * Usuario se registra → Profile creado con phone=null, photo=null
     * Usuario va a "Mi perfil" → Ve campos vacíos
     * Usuario completa teléfono y sube foto
     * Usuario hace PUT /api/profiles/{id} → Perfil actualizado
     * ```
     * 
     * Caso de uso 2: Ver perfil después de login OAuth
     * ```
     * Usuario hace login con Google → Profile creado con photo de Google
     * Usuario va a "Mi perfil" → Ve su foto de Google, teléfono vacío
     * Usuario agrega teléfono si lo desea
     * ```
     * 
     * RELACIÓN User ↔ Profile (1:1):
     * - Un usuario tiene UN perfil
     * - Un perfil pertenece a UN usuario
     * - Se usa ProfileRepository.findByUser() para buscar
     * 
     * Ventajas de esta separación:
     * - User: Datos de autenticación (email, password, authProvider)
     * - Profile: Datos de presentación (phone, photo)
     * - Queries más eficientes (solo cargar lo necesario)
     * - Facilita agregar más campos al perfil sin tocar User
     * 
     * IMPORTANTE: Gracias a la implementación automatizada, este endpoint
     * SIEMPRE retornará un perfil. Si el perfil no existe (caso edge),
     * retorna 404 para que el frontend pueda manejarlo.
     * 
     * @param authHeader Header Authorization con formato "Bearer {token}"
     * @return ResponseEntity con el perfil o código de error
     */
    @GetMapping("/me")
    public ResponseEntity<?> getMyProfile(@RequestHeader(value = "Authorization", required = false) String authHeader) {
        try {
            // ✅ LOG 1: Ver si el header llega
            System.out.println("🔍 [ProfileController] Header Authorization recibido: " + authHeader);

            if (authHeader == null || authHeader.isEmpty()) {
                System.out.println("❌ [ProfileController] Header Authorization es NULL o vacío");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "Authorization header no proporcionado"));
            }

            // ✅ LOG 2: Ver el token extraído
            String token = authHeader.replace("Bearer ", "");
            System.out.println("🔍 [ProfileController] Token extraído: " + token.substring(0, Math.min(50, token.length())) + "...");

            // ✅ LOG 3: Ver si getUserFromToken funciona
            User user = jwtService.getUserFromToken(token);
            System.out.println("🔍 [ProfileController] User from token: " + (user != null ? user.getEmail() : "NULL"));

            if (user == null) {
                System.out.println("❌ [ProfileController] getUserFromToken retornó null");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "Token inválido o expirado"));
            }

            // ✅ LOG 4: Ver si se encuentra el perfil
            System.out.println("🔍 [ProfileController] Buscando perfil para usuario: " + user.getEmail());
            Profile profile = profileRepository.findByUser(user);
            System.out.println("🔍 [ProfileController] Perfil encontrado: " + (profile != null ? profile.getId() : "NULL"));

            if (profile == null) {
                System.out.println("❌ [ProfileController] Perfil no encontrado en BD para usuario: " + user.getEmail());
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(Map.of(
                                "error", "Perfil no encontrado",
                                "message", "El usuario no tiene un perfil asociado"
                        ));
            }

            System.out.println("✅ [ProfileController] Retornando perfil: " + profile.getId());
            return ResponseEntity.ok(profile);

        } catch (Exception e) {
            System.out.println("❌ [ProfileController] Exception: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Error: " + e.getMessage()));
        }
    }

    /**
     * Crea un perfil automáticamente si el usuario no tiene uno.
     * 
     * Este endpoint es útil como recuperación de emergencia cuando un usuario
     * fue creado sin perfil (ej: creado manualmente por API sin usar register()).
     * 
     * FLUJO:
     * 1. Usuario autenticado solicita GET /api/profiles/create-if-missing
     * 2. Backend extrae el usuario del JWT
     * 3. Backend verifica si el usuario tiene perfil
     * 4. Si existe: retorna el perfil existente
     * 5. Si no existe: crea un perfil vacío y retorna
     * 
     * Este es un endpoint seguro porque:
     * - Solo funciona para el usuario autenticado (no puede crear perfiles ajenos)
     * - Requiere token JWT válido
     * - Usa la ruta /api/profiles/create-if-missing que es clara
     * 
     * @param authHeader Header Authorization con formato "Bearer {token}"
     * @return Perfil existente o nuevo (creado si faltaba)
     */
    @GetMapping("/create-if-missing")
    public ResponseEntity<?> createProfileIfMissing(@RequestHeader("Authorization") String authHeader) {
        try {
            // Validar que el header esté presente
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "Token no proporcionado"));
            }

            // Extraer el token JWT del header
            String token = authHeader.replace("Bearer ", "");
            
            // Obtener el usuario completo desde el token
            User user = jwtService.getUserFromToken(token);
            
            // Validar que el token sea válido
            if (user == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "Token inválido o expirado"));
            }

            System.out.println("🔄 [ProfileController] Verificando/creando perfil para: " + user.getEmail());
            
            // Crear perfil si falta o retornar el existente
            Profile profile = profileService.createIfMissing(user);
            
            return ResponseEntity.ok(Map.of(
                    "message", "Perfil listo para usar",
                    "profile", profile
            ));
            
        } catch (Exception e) {
            System.out.println("❌ [ProfileController] Error en create-if-missing: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Error al crear perfil: " + e.getMessage()));
        }
    }

    /**
     * Cambia la contraseña del usuario autenticado actual.
     * 
     * Este endpoint permite que un usuario logueado cambie su contraseña
     * de forma segura. Solo funciona para usuarios con autenticación LOCAL
     * (no para usuarios registrados con OAuth como Google o GitHub).
     * 
     * VALIDACIONES:
     * - Requiere el JWT en el Authorization header
     * - Requiere que el usuario sea de tipo LOCAL (no OAuth)
     * - Verifica que la contraseña actual sea correcta
     * - La nueva contraseña debe tener al menos 6 caracteres
     * - La nueva contraseña no puede ser igual a la actual
     * - Las dos nuevas contraseñas deben coincidir
     * 
     * FLUJO:
     * 1. Usuario en su perfil solicita cambiar contraseña
     * 2. Frontend abre formulario con 3 campos: actual, nueva, confirmar
     * 3. Frontend envía POST /api/profiles/change-password con JWT
     * 4. Backend extrae usuario del JWT
     * 5. Backend verifica contraseña actual
     * 6. Backend encripta y guarda nueva contraseña
     * 7. Backend retorna mensaje de éxito
     * 
     * Ejemplo de uso desde frontend:
     * ```javascript
     * const changePassword = async () => {
     *   const token = localStorage.getItem('jwt');
     *   const response = await fetch('/api/profiles/change-password', {
     *     method: 'POST',
     *     headers: {
     *       'Authorization': `Bearer ${token}`,
     *       'Content-Type': 'application/json'
     *     },
     *     body: JSON.stringify({
     *       currentPassword: document.getElementById('current').value,
     *       newPassword: document.getElementById('new').value,
     *       confirmPassword: document.getElementById('confirm').value
     *     })
     *   });
     *   
     *   if (response.ok) {
     *     alert('Contraseña cambiada exitosamente');
     *     // Limpiar formulario
     *   } else {
     *     const { error } = await response.json();
     *     alert('Error: ' + error);
     *   }
     * };
     * ```
     * 
     * Petición JSON (ejemplo):
     * ```json
     * {
     *   "currentPassword": "miContraseñaActual123",
     *   "newPassword": "miNuevaContraseña456",
     *   "confirmPassword": "miNuevaContraseña456"
     * }
     * ```
     * 
     * Respuesta exitosa (200 OK):
     * ```json
     * {
     *   "message": "Contraseña actualizada exitosamente"
     * }
     * ```
     * 
     * Respuestas de error (400/401):
     * ```json
     * {
     *   "error": "La contraseña actual es incorrecta"
     * }
     * ```
     * 
     * @param authHeader Header Authorization con formato "Bearer {token}"
     * @param request Map con: currentPassword, newPassword, confirmPassword
     * @return ResponseEntity con mensaje de éxito o error
     */
    @PostMapping("/change-password")
    public ResponseEntity<?> changePassword(
            @RequestHeader("Authorization") String authHeader,
            @RequestBody Map<String, String> request) {
        try {
            // Validar que el header esté presente
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "Token no proporcionado"));
            }

            // Extraer el token JWT
            String token = authHeader.replace("Bearer ", "");
            
            // Obtener el usuario desde el token
            User user = jwtService.getUserFromToken(token);
            
            if (user == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "Token inválido o expirado"));
            }

            // Obtener campos del request
            String currentPassword = request.get("currentPassword");
            String newPassword = request.get("newPassword");
            String confirmPassword = request.get("confirmPassword");

            // Validar que los campos estén presentes
            if (currentPassword == null || currentPassword.isEmpty()) {
                return ResponseEntity.badRequest()
                        .body(Map.of("error", "Debe proporcionar su contraseña actual"));
            }
            if (newPassword == null || newPassword.isEmpty()) {
                return ResponseEntity.badRequest()
                        .body(Map.of("error", "Debe proporcionar la nueva contraseña"));
            }
            if (confirmPassword == null || confirmPassword.isEmpty()) {
                return ResponseEntity.badRequest()
                        .body(Map.of("error", "Debe confirmar la nueva contraseña"));
            }

            // Validar que las nuevas contraseñas coincidan
            if (!newPassword.equals(confirmPassword)) {
                return ResponseEntity.badRequest()
                        .body(Map.of("error", "Las nuevas contraseñas no coinciden"));
            }

            // Llamar al servicio para cambiar contraseña
            securityService.changePassword(user, currentPassword, newPassword);

            return ResponseEntity.ok(Map.of(
                    "message", "Contraseña actualizada exitosamente"
            ));

        } catch (RuntimeException e) {
            // Errores de validación del servicio
            return ResponseEntity.badRequest()
                    .body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            // Errores inesperados
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Error al cambiar contraseña: " + e.getMessage()));
        }
    }
}
