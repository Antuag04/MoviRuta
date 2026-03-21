package com.security.mssecurity.Controllers;

import com.security.mssecurity.Models.Profile;
import com.security.mssecurity.Models.User;
import com.security.mssecurity.Repositories.ProfileRepository;
import com.security.mssecurity.Services.JwtService;
import com.security.mssecurity.Services.ProfileService;
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
    public ResponseEntity<?> getMyProfile(@RequestHeader("Authorization") String authHeader) {
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
            
            // Buscar el perfil asociado al usuario
            // Utilizamos ProfileRepository.findByUser() que implementamos
            Profile profile = profileRepository.findByUser(user);
            
            // Validar que el perfil exista
            // En teoría siempre existe porque se crea automáticamente,
            // pero validamos por seguridad
            if (profile == null) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of(
                        "error", "Perfil no encontrado",
                        "message", "El usuario no tiene un perfil asociado. Esto no debería ocurrir."
                    ));
            }
            
            // Retornar el perfil
            return ResponseEntity.ok(profile);
            
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "Error al obtener perfil: " + e.getMessage()));
        }
    }
}
