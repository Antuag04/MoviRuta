package com.security.mssecurity.Services;

import com.security.mssecurity.Models.Role;
import com.security.mssecurity.Models.User;
import com.security.mssecurity.Models.UserRole;
import com.security.mssecurity.Repositories.RoleRepository;
import com.security.mssecurity.Repositories.UserRepository;
import com.security.mssecurity.Repositories.UserRoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * Servicio principal de autenticación y registro de usuarios.
 * 
 * Este servicio gestiona las operaciones fundamentales de seguridad:
 * - Registro de nuevos usuarios con validación de datos
 * - Inicio de sesión tradicional (email/contraseña)
 * - Asignación automática del rol "CIUDADANO" a nuevos usuarios
 * 
 * Para la autenticación OAuth 2.0, se utilizan servicios especializados
 * por proveedor (GoogleOAuthService, GitHubOAuthService, MicrosoftOAuthService).
 * 
 * @see GoogleOAuthService
 * @see GitHubOAuthService
 * @see MicrosoftOAuthService
 */
@Service
public class SecurityService {

    @Autowired
    private UserRepository theUserRepository;

    @Autowired
    private EncryptionService theEncryptionService;

    @Autowired
    private JwtService theJwtService;

    @Autowired
    private RoleRepository theRoleRepository;

    @Autowired
    private UserRoleRepository theUserRoleRepository;

    /**
     * Autentica un usuario mediante email y contraseña.
     * 
     * El proceso de autenticación incluye:
     * 1. Búsqueda del usuario por email
     * 2. Verificación del proveedor de autenticación
     * 3. Validación de la contraseña mediante BCrypt
     * 4. Generación del token JWT si las credenciales son válidas
     * 
     * @param theNewUser Objeto User con email y contraseña a validar
     * @return Token JWT si la autenticación es exitosa, null si las credenciales son inválidas
     * @throws RuntimeException Si el usuario fue registrado mediante OAuth
     */
    public String login(User theNewUser) {
        User theActualUser = this.theUserRepository.getUserByEmail(theNewUser.getEmail());
        
        if (theActualUser == null) {
            return null;
        }
        
        if ("GOOGLE".equals(theActualUser.getAuthProvider())) {
            throw new RuntimeException("Este usuario debe iniciar sesión con Google");
        }
        
        if (theEncryptionService.verifyPassword(theNewUser.getPassword(), theActualUser.getPassword())) {
            return theJwtService.generateToken(theActualUser);
        }
        
        return null;
    }

    /**
     * Registra un nuevo usuario en el sistema.
     * 
     * El proceso de registro incluye:
     * 1. Validación de campos obligatorios (nombre, email, contraseña)
     * 2. Verificación de que el email no esté registrado
     * 3. Encriptación de la contraseña con BCrypt
     * 4. Asignación del proveedor "LOCAL"
     * 5. Persistencia del usuario en la base de datos
     * 6. Asignación automática del rol "CIUDADANO"
     * 
     * @param newUser Objeto User con los datos del nuevo usuario
     * @return Usuario creado con su ID asignado
     * @throws RuntimeException Si los datos son inválidos o el email ya existe
     */
    public User register(User newUser) {
        if (newUser.getName() == null || newUser.getName().trim().isEmpty()) {
            throw new RuntimeException("El nombre es obligatorio");
        }
        if (newUser.getEmail() == null || newUser.getEmail().trim().isEmpty()) {
            throw new RuntimeException("El email es obligatorio");
        }
        if (newUser.getPassword() == null || newUser.getPassword().trim().isEmpty()) {
            throw new RuntimeException("La contraseña es obligatoria");
        }

        User existing = theUserRepository.getUserByEmail(newUser.getEmail());
        if (existing != null) {
            throw new RuntimeException("El email ya está registrado");
        }

        newUser.setPassword(theEncryptionService.encryptPassword(newUser.getPassword()));
        newUser.setAuthProvider("LOCAL");

        User savedUser = theUserRepository.save(newUser);

        Role ciudadanoRole = theRoleRepository.findByName("CIUDADANO");
        if (ciudadanoRole != null) {
            UserRole userRole = new UserRole(savedUser, ciudadanoRole);
            theUserRoleRepository.save(userRole);
        } else {
            System.out.println("ADVERTENCIA: El rol 'Ciudadano' no existe en la base de datos");
        }

        return savedUser;
    }
}
