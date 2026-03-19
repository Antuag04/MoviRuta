package com.security.mssecurity.Services;

import com.security.mssecurity.Models.*;
import com.security.mssecurity.Repositories.PermissionRepository;
import com.security.mssecurity.Repositories.RolePermissionRepository;
import com.security.mssecurity.Repositories.UserRepository;
import com.security.mssecurity.Repositories.UserRoleRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ValidatorsService {
    @Autowired
    private JwtService jwtService;

    @Autowired
    private PermissionRepository thePermissionRepository;
    @Autowired
    private UserRepository theUserRepository;
    @Autowired
    private RolePermissionRepository theRolePermissionRepository;

    @Autowired
    private UserRoleRepository theUserRoleRepository;

    private static final String BEARER_PREFIX = "Bearer ";
    public boolean  validationRolePermission(HttpServletRequest request,
                                             String url,
                                             String method){
        boolean success=false;
        User theUser=this.getUser(request);
        if(theUser!=null){
            List<UserRole> roles=this.theUserRoleRepository.getRolesByUser(theUser.getId());
            System.out.println("Antes URL "+url+" metodo "+method);
            url = url.replaceAll("[0-9a-fA-F]{24}|\\d+", "?");
            System.out.println("URL "+url+" metodo "+method);
            Permission thePermission=this.thePermissionRepository.getPermission(url,method);

            int i=0;
            while(i<roles.size() && success==false){
                UserRole actual=roles.get(i);
                Role theRole=actual.getRole();
                if(theRole!=null && thePermission!=null){
                    System.out.println("Rol "+theRole.getId()+ " Permission "+thePermission.getId());
                    RolePermission theRolePermission=this.theRolePermissionRepository.getRolePermission(theRole.getId(),thePermission.getId());
                    if (theRolePermission!=null){
                        success=true;
                    }
                }else{
                    success=false;
                }
                i+=1;
            }

        }
        return success;
    }

    /// analiza el token y descifra los datos para re armar el usuario
    /// @param request que contiene el token
    /// @return el usuario de base de datos que tiene el id presente en el token
    public User getUser(final HttpServletRequest request) {
        User theUser=null;
        String authorizationHeader = request.getHeader("Authorization");
        System.out.println("Header "+authorizationHeader);
        if (authorizationHeader != null && authorizationHeader.startsWith(BEARER_PREFIX)) {
            String token = authorizationHeader.substring(BEARER_PREFIX.length());
            System.out.println("Bearer Token: " + token);
            User theUserFromToken=jwtService.getUserFromToken(token);
            if(theUserFromToken!=null) {
                theUser= this.theUserRepository.findById(theUserFromToken.getId())
                        .orElse(null);

            }
        }
        return theUser;
    }
}





