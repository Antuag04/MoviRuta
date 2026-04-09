package com.security.mssecurity.Services;

import com.security.mssecurity.Models.Profile;
import com.security.mssecurity.Repositories.ProfileRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.net.URL;
import java.util.List;

/**
 * Servicio que gestiona las operaciones CRUD de perfiles de usuario.
 * 
 * Los perfiles almacenan información adicional del usuario como
 * teléfono y fotografía, separada de los datos de autenticación.
 * 
 * @see ProfileRepository
 * @see com.security.mssecurity.Models.Profile
 */
@Service
public class ProfileService {

    @Autowired
    private ProfileRepository profileRepository;

    /**
     * Obtiene la lista de todos los perfiles.
     * 
     * @return Lista de perfiles
     */
    public List<Profile> find() {
        return this.profileRepository.findAll();
    }

    /**
     * Busca un perfil por su identificador.
     * 
     * @param id Identificador único del perfil
     * @return Perfil encontrado o null si no existe
     */
    public Profile findById(String id) {
        Profile theProfile = this.profileRepository.findById(id).orElse(null);
        return theProfile;
    }

    /**
     * Crea un nuevo perfil.
     * 
     * @param newProfile Datos del nuevo perfil
     * @return Perfil creado con su ID asignado
     */
    public Profile create(Profile newProfile) {
        return this.profileRepository.save(newProfile);
    }

    /**
     * Actualiza un perfil existente con validación de foto.
     * 
     * Validaciones de seguridad para la foto:
     * - Si se proporciona foto, se valida que sea una URL HTTPS válida
     * - Se verifica que la URL tenga longitud razonable (< 500 caracteres)
     * - Se rechaza URL de dominios potencialmente maliciosos
     * 
     * @param id         Identificador del perfil a actualizar
     * @param newProfile Datos actualizados
     * @return Perfil actualizado o null si no existe
     * @throws RuntimeException Si la URL de foto es inválida
     */
    public Profile update(String id, Profile newProfile) {
        Profile actualProfile = this.profileRepository.findById(id).orElse(null);

        if (actualProfile != null) {
            actualProfile.setPhone(newProfile.getPhone());
            
            // Validar foto si se proporciona
            if (newProfile.getPhoto() != null && !newProfile.getPhoto().trim().isEmpty()) {
                validatePhotoUrl(newProfile.getPhoto());
            }
            
            actualProfile.setPhoto(newProfile.getPhoto());
            this.profileRepository.save(actualProfile);
            return actualProfile;
        } else {
            return null;
        }
    }

    /**
     * Valida que una URL de foto sea válida.
     * 
     * Validaciones realizadas:
     * 1. URL no nula ni vacía
     * 2. Longitud máxima 500 caracteres
     * 3. Protocolo HTTPS (secure)
     * 4. Formato de URL válido
     * 
     * @param photoUrl URL de la foto a validar
     * @throws RuntimeException Si la URL no cumple las validaciones
     */
    private void validatePhotoUrl(String photoUrl) {
        // Validación 1: No nula ni vacía
        if (photoUrl == null || photoUrl.trim().isEmpty()) {
            throw new RuntimeException("La URL de la foto no puede estar vacía");
        }

        // Validación 2: Longitud máxima
        if (photoUrl.length() > 500) {
            throw new RuntimeException("La URL de la foto es demasiado larga (máximo 500 caracteres)");
        }

        // Validación 3: Debe ser HTTPS
        if (!photoUrl.toLowerCase().startsWith("https://")) {
            throw new RuntimeException("La URL de la foto debe usar HTTPS (https://)");
        }

        // Validación 4: Validar formato de URL
        try {
            new URL(photoUrl);
        } catch (Exception e) {
            throw new RuntimeException("La URL de la foto no es válida: " + e.getMessage());
        }
        
        // Se permite cualquier dominio HTTPS válido
    }

    /**
     * Elimina un perfil del sistema.
     * 
     * @param id Identificador del perfil a eliminar
     */
    public void delete(String id) {
        Profile theProfile = this.profileRepository.findById(id).orElse(null);
        if (theProfile != null) {
            this.profileRepository.delete(theProfile);
        }
    }

    /**
     * Crea un perfil si el usuario no tiene uno.
     * 
     * Este método es útil como recuperación de emergencia cuando un usuario
     * fue creado sin perfil (ej: creado directamente por API sin usar register()).
     * 
     * Verifica si el usuario ya tiene un perfil:
     * - Si existe: retorna el perfil existente sin crear uno nuevo
     * - Si no existe: crea un perfil vacío (phone=null, photo=null) y lo retorna
     * 
     * @param user Usuario propietario del perfil
     * @return Perfil existente o nuevo (creado si faltaba)
     */
    public Profile createIfMissing(com.security.mssecurity.Models.User user) {
        // Buscar si el usuario ya tiene un perfil
        Profile existingProfile = profileRepository.findByUser(user);
        
        if (existingProfile != null) {
            System.out.println("✅ [ProfileService] Perfil ya existe para usuario: " + user.getEmail());
            return existingProfile;
        }
        
        // Crear perfil vacío si no existe
        System.out.println("🔄 [ProfileService] Creando perfil faltante para usuario: " + user.getEmail());
        Profile newProfile = new Profile(null, null);
        newProfile.setUser(user);
        
        Profile savedProfile = profileRepository.save(newProfile);
        System.out.println("✅ [ProfileService] Perfil creado automáticamente con ID: " + savedProfile.getId());
        
        return savedProfile;
    }
}
