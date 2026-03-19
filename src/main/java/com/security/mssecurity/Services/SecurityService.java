package com.security.mssecurity.Services;

import com.security.mssecurity.Models.User;
import com.security.mssecurity.Repositories.UserRepository;
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

    public String login(User theNewUser) {
        User theActualUser = this.theUserRepository.getUserByEmail(theNewUser.getEmail());
        if (theActualUser != null &&
                theEncryptionService.verifyPassword(theNewUser.getPassword(), theActualUser.getPassword())) {
            return theJwtService.generateToken(theActualUser);
        }
        return null;
    }


    public User register(User newUser) {
        User existing = theUserRepository.getUserByEmail(newUser.getEmail());
        if (existing != null) {
            return null; // ya existe
        }
        newUser.setPassword(theEncryptionService.encryptPassword(newUser.getPassword()));
        return theUserRepository.save(newUser);
    }
    /*
    public boolean permissionsValidation(final HttpServletRequest request,
                                         @RequestBody Permission thePermission) {
        boolean success=this.theValidatorsService.validationRolePermission(request,thePermission.getUrl(),thePermission.getMethod());
        return success;
    }
    */

}
