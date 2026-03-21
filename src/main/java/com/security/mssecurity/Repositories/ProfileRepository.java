package com.security.mssecurity.Repositories;

import com.security.mssecurity.Models.Profile;
import com.security.mssecurity.Models.User;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

/**
 * Repositorio para acceso a datos de la colección de perfiles en MongoDB.
 * 
 * Proporciona operaciones CRUD básicas para la gestión de perfiles
 * de usuario en el sistema, así como consultas especializadas para
 * búsqueda de perfiles por usuario.
 * 
 * Los perfiles almacenan información adicional del usuario que no es
 * necesaria para la autenticación (teléfono, foto). Esta separación
 * entre User (datos de autenticación) y Profile (datos de perfil)
 * sigue el principio de separación de responsabilidades.
 * 
 * @see Profile
 * @see User
 */
@Repository
public interface ProfileRepository extends MongoRepository<Profile, String> {
    
    /**
     * Busca el perfil asociado a un usuario específico.
     * 
     * Relación: User (1) ↔ Profile (1)
     * Un usuario tiene máximo un perfil, y un perfil pertenece a un solo usuario.
     * Esta es una relación uno-a-uno bidireccional.
     * 
     * Este método es útil para:
     * - Obtener el perfil del usuario autenticado actual
     * - Validar si un usuario ya tiene perfil antes de crearlo
     * - Cargar datos de perfil sin necesidad del ID del profile
     * - Operaciones donde solo se tiene acceso al User pero se necesita el Profile
     * 
     * Ejemplo de uso:
     * ```java
     * // Obtener perfil del usuario autenticado
     * User currentUser = getUserFromToken(jwt);
     * Profile userProfile = profileRepository.findByUser(currentUser);
     * 
     * if (userProfile != null) {
     *     String phone = userProfile.getPhone();
     *     String photo = userProfile.getPhoto();
     * }
     * ```
     * 
     * NOTA: Si el usuario no tiene perfil asociado, este método retorna null.
     * En el flujo implementado, todo usuario registrado tiene un perfil creado
     * automáticamente, pero esta validación es importante para casos edge.
     * 
     * @param user Usuario propietario del perfil
     * @return Profile asociado al usuario si existe, null si el usuario no tiene perfil
     */
    Profile findByUser(User user);
}
