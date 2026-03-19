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

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private ProfileRepository theProfileRepository;
    /**
     * Permite asociar un usuario y un perfil. Para que funcione ambos
     * ya deben de existir en la base de datos
     *
     * @param userId
     * @param profileId
     * @return
     */

    @Autowired
    private SessionRepository sessionRepository;
    /**
     * Permite asociar un usuario y una sesión. Para que funcione ambos
     * ya deben de existir en la base de datos
     *
     * @param userId
     * @param sessionId
     * @return
     */

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private EncryptionService theEncryptionService;



    /// Metodos para buscar, crear, actualizar y eliminar usuarios
    public List<User> find() {

        return userRepository.findAll();
    }

    public User findById(String id) {
        return userRepository.findById(id).orElse(null);
    }

    public User create(User user) {
        User existing = userRepository.getUserByEmail(user.getEmail());
        if (existing != null) {
            throw new RuntimeException("El correo ya se encuentra registrado");
        }
        user.setPassword(theEncryptionService.encryptPassword(user.getPassword()));
        return this.userRepository.save(user);
    }

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

    public void delete(String id) {
        User user = userRepository.findById(id).orElse(null);
        if (user != null) {
            userRepository.delete(user);
        }
    }

    /// Metodos para asociar un usuario con un perfil

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

    /// Metodos para asociar una sesion con un usuario que ya tiene perfil

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
