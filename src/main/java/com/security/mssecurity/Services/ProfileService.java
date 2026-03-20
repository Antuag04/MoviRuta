package com.security.mssecurity.Services;

import com.security.mssecurity.Models.Profile;
import com.security.mssecurity.Repositories.ProfileRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

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
     * Actualiza un perfil existente.
     * 
     * @param id         Identificador del perfil a actualizar
     * @param newProfile Datos actualizados
     * @return Perfil actualizado o null si no existe
     */
    public Profile update(String id, Profile newProfile) {
        Profile actualProfile = this.profileRepository.findById(id).orElse(null);

        if (actualProfile != null) {
            actualProfile.setPhone(newProfile.getPhone());
            actualProfile.setPhoto(newProfile.getPhoto());
            this.profileRepository.save(actualProfile);
            return actualProfile;
        } else {
            return null;
        }
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
}
