package com.security.mssecurity.Services;

import com.security.mssecurity.Models.Role;
import com.security.mssecurity.Models.User;
import com.security.mssecurity.Models.Profile;
import com.security.mssecurity.Models.Session;
import com.security.mssecurity.Repositories.RoleRepository;
import com.security.mssecurity.Repositories.SessionRepository;
import com.security.mssecurity.Repositories.ProfileRepository;
import com.security.mssecurity.Repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.List;

/**
 * Servicio que gestiona las operaciones CRUD de usuarios y sus relaciones.
 * 
 * Este servicio proporciona funcionalidades para:
 * - Gestión básica de usuarios (crear, leer, actualizar, eliminar)
 * - Asociación de usuarios con perfiles
 * - Asociación de usuarios con sesiones
 * 
 * La contraseña de los usuarios se encripta automáticamente antes de almacenarse.
 * 
 * @see UserRepository
 * @see EncryptionService
 */
@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private ProfileRepository theProfileRepository;

    @Autowired
    private SessionRepository sessionRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private EncryptionService theEncryptionService;

    /**
     * Obtiene la lista de todos los usuarios registrados.
     * 
     * @return Lista de usuarios
     */
    public List<User> find() {
        return userRepository.findAll();
    }

    /**
     * Busca un usuario por su identificador.
     * 
     * @param id Identificador único del usuario
     * @return Usuario encontrado o null si no existe
     */
    public User findById(String id) {
        return userRepository.findById(id).orElse(null);
    }

    /**
     * Crea un nuevo usuario en el sistema.
     * 
     * Valida que el email no esté registrado y encripta la contraseña
     * antes de almacenar el usuario.
     * 
     * @param user Datos del nuevo usuario
     * @return Usuario creado con su ID asignado
     * @throws RuntimeException Si el email ya está registrado
     */
    public User create(User user) {
        User existing = userRepository.getUserByEmail(user.getEmail());
        if (existing != null) {
            throw new RuntimeException("El correo ya se encuentra registrado");
        }
        user.setPassword(theEncryptionService.encryptPassword(user.getPassword()));
        return this.userRepository.save(user);
    }

    /**
     * Actualiza los datos de un usuario existente.
     * 
     * La contraseña se re-encripta al actualizar.
     * 
     * @param id         Identificador del usuario a actualizar
     * @param userUpdate Datos actualizados
     * @return Usuario actualizado o null si no existe
     */
    public User update(String id, User userUpdate) {
        User currentUser = this.userRepository.findById(id).orElse(null);

        if (userUpdate != null) {
            currentUser.setName(userUpdate.getName());
            currentUser.setEmail(userUpdate.getEmail());
            currentUser.setPassword(userUpdate.getPassword());
            currentUser.setPassword(theEncryptionService.encryptPassword(currentUser.getPassword()));
            this.userRepository.save(currentUser);
            return userUpdate;
        } else {
            return null;
        }
    }

    /**
     * Elimina un usuario del sistema.
     * 
     * @param id Identificador del usuario a eliminar
     */
    public void delete(String id) {
        User user = userRepository.findById(id).orElse(null);
        if (user != null) {
            userRepository.delete(user);
        }
    }

    /**
     * Asocia un perfil existente a un usuario.
     * 
     * Ambas entidades deben existir previamente en la base de datos.
     * 
     * @param userId    Identificador del usuario
     * @param profileId Identificador del perfil
     * @return true si la asociación fue exitosa, false si no se encontraron las entidades
     */
    public boolean addProfile(String userId, String profileId) {
        User theUser = this.userRepository.findById(userId).orElse(null);
        Profile theProfile = this.theProfileRepository.findById(profileId).orElse(null);
        if (theUser != null && theProfile != null) {
            theProfile.setUser(theUser);
            this.theProfileRepository.save(theProfile);
            return true;
        } else {
            return false;
        }
    }

    /**
     * Elimina la asociación entre un usuario y su perfil.
     * 
     * @param userId    Identificador del usuario
     * @param profileId Identificador del perfil
     * @return true si la operación fue exitosa, false si no se encontraron las entidades
     */
    public boolean removeProfile(String userId, String profileId) {
        User theUser = this.userRepository.findById(userId).orElse(null);
        Profile theProfile = this.theProfileRepository.findById(profileId).orElse(null);
        if (theUser != null && theProfile != null) {
            theProfile.setUser(null);
            this.theProfileRepository.save(theProfile);
            return true;
        } else {
            return false;
        }
    }

    /**
     * Asocia una sesión existente a un usuario.
     * 
     * @param userId    Identificador del usuario
     * @param sessionId Identificador de la sesión
     * @return true si la asociación fue exitosa, false si no se encontraron las entidades
     */
    public boolean addSession(String userId, String sessionId) {
        User theUser = this.userRepository.findById(userId).orElse(null);
        Session theSession = this.sessionRepository.findById(sessionId).orElse(null);
        if (theUser != null && theSession != null) {
            theSession.setUser(theUser);
            this.sessionRepository.save(theSession);
            return true;
        } else {
            return false;
        }
    }

    /**
     * Elimina la asociación entre un usuario y una sesión.
     * 
     * @param userId    Identificador del usuario
     * @param sessionId Identificador de la sesión
     * @return true si la operación fue exitosa, false si no se encontraron las entidades
     */
    public boolean removeSession(String userId, String sessionId) {
        User theUser = this.userRepository.findById(userId).orElse(null);
        Session theSession = this.sessionRepository.findById(sessionId).orElse(null);
        if (theUser != null && theSession != null) {
            theSession.setUser(null);
            this.sessionRepository.save(theSession);
            return true;
        } else {
            return false;
        }
    }
}
