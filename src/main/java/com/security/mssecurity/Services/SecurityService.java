package com.security.mssecurity.Services;

import com.security.mssecurity.Models.Role;
import com.security.mssecurity.Models.User;
import com.security.mssecurity.Models.UserRole;
import com.security.mssecurity.Repositories.RoleRepository;
import com.security.mssecurity.Repositories.UserRepository;
import com.security.mssecurity.Repositories.UserRoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;


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

    public String login(User theNewUser) {
        User theActualUser = this.theUserRepository.getUserByEmail(theNewUser.getEmail());
        
        if (theActualUser == null) {
            return null; // Usuario no existe
        }
        
        // Verificar si el usuario se registró con Google
        if ("GOOGLE".equals(theActualUser.getAuthProvider())) {
            throw new RuntimeException("Este usuario debe iniciar sesión con Google");
        }
        
        // Flujo normal: verificar contraseña
        if (theEncryptionService.verifyPassword(theNewUser.getPassword(), theActualUser.getPassword())) {
            return theJwtService.generateToken(theActualUser);
        }
        
        return null;
    }


    public User register(User newUser) {
        // 1. Validaciones
        if (newUser.getName() == null || newUser.getName().trim().isEmpty()) {
            throw new RuntimeException("El nombre es obligatorio");
        }
        if (newUser.getEmail() == null || newUser.getEmail().trim().isEmpty()) {
            throw new RuntimeException("El email es obligatorio");
        }
        if (newUser.getPassword() == null || newUser.getPassword().trim().isEmpty()) {
            throw new RuntimeException("La contraseña es obligatoria");
        }

        // 2. Evitar email duplicado
        User existing = theUserRepository.getUserByEmail(newUser.getEmail());
        if (existing != null) {
            throw new RuntimeException("El email ya está registrado");
        }

        // 3. Encriptar contraseña
        newUser.setPassword(theEncryptionService.encryptPassword(newUser.getPassword()));
        
        // 4. Establecer authProvider como LOCAL (registro tradicional)
        newUser.setAuthProvider("LOCAL");

        // 5. Guardar usuario
        User savedUser = theUserRepository.save(newUser);

        // 6. ASIGNAR ROL "CIUDADANO" AUTOMÁTICAMENTE
        Role ciudadanoRole = theRoleRepository.findByName("CIUDADANO");
        if (ciudadanoRole != null) {
            UserRole userRole = new UserRole(savedUser, ciudadanoRole);
            theUserRoleRepository.save(userRole);
        } else {
            // Advertencia: el rol "Ciudadano" no existe en la BD
            System.out.println("ADVERTENCIA: El rol 'Ciudadano' no existe en la base de datos");
        }

        return savedUser;
    }
    /*
    public boolean permissionsValidation(final HttpServletRequest request,
                                         @RequestBody Permission thePermission) {
        boolean success=this.theValidatorsService.validationRolePermission(request,thePermission.getUrl(),thePermission.getMethod());
        return success;
    }
    */

}
