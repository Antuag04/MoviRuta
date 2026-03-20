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

/**
 * Servicio encargado de la validación de permisos y autenticación de usuarios.
 * 
 * Este servicio implementa la lógica central del sistema de control de acceso
 * basado en roles (RBAC), verificando que los usuarios tengan los permisos
 * necesarios para acceder a los recursos solicitados.
 * 
 * El proceso de validación consiste en:
 * 1. Extraer el token JWT del header Authorization
 * 2. Obtener el usuario asociado al token
 * 3. Consultar los roles asignados al usuario
 * 4. Verificar si alguno de los roles tiene el permiso requerido
 * 
 * @see com.security.mssecurity.Interceptors.SecurityInterceptor
 */
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

    /**
     * Prefijo estándar para tokens Bearer en el header Authorization.
     */
    private static final String BEARER_PREFIX = "Bearer ";

    /**
     * Valida si el usuario tiene permiso para acceder al recurso solicitado.
     * 
     * El método realiza las siguientes operaciones:
     * 1. Extrae el usuario del token JWT
     * 2. Normaliza la URL reemplazando IDs dinámicos por "?"
     * 3. Busca el permiso correspondiente a la URL y método HTTP
     * 4. Verifica si algún rol del usuario tiene asignado ese permiso
     * 
     * @param request Objeto HttpServletRequest con el token en el header
     * @param url     URL del recurso solicitado
     * @param method  Método HTTP de la petición (GET, POST, PUT, DELETE)
     * @return true si el usuario tiene permiso, false en caso contrario
     */
    public boolean validationRolePermission(HttpServletRequest request,
                                             String url,
                                             String method) {
        boolean success = false;
        User theUser = this.getUser(request);
        
        if (theUser != null) {
            List<UserRole> roles = this.theUserRoleRepository.getRolesByUser(theUser.getId());
            
            System.out.println("Antes URL " + url + " metodo " + method);
            url = url.replaceAll("[0-9a-fA-F]{24}|\\d+", "?");
            System.out.println("URL " + url + " metodo " + method);
            
            Permission thePermission = this.thePermissionRepository.getPermission(url, method);

            int i = 0;
            while (i < roles.size() && success == false) {
                UserRole actual = roles.get(i);
                Role theRole = actual.getRole();
                
                if (theRole != null && thePermission != null) {
                    System.out.println("Rol " + theRole.getId() + " Permission " + thePermission.getId());
                    RolePermission theRolePermission = this.theRolePermissionRepository
                            .getRolePermission(theRole.getId(), thePermission.getId());
                    
                    if (theRolePermission != null) {
                        success = true;
                    }
                } else {
                    success = false;
                }
                i += 1;
            }
        }
        return success;
    }

    /**
     * Extrae el usuario autenticado a partir del token JWT en la petición.
     * 
     * El método realiza las siguientes operaciones:
     * 1. Obtiene el header Authorization de la petición
     * 2. Verifica que comience con el prefijo "Bearer "
     * 3. Extrae el token y decodifica la información del usuario
     * 4. Consulta la base de datos para obtener el usuario completo
     * 
     * @param request Objeto HttpServletRequest que contiene el token en el header
     * @return Usuario encontrado en la base de datos, o null si el token es inválido
     */
    public User getUser(final HttpServletRequest request) {
        User theUser = null;
        String authorizationHeader = request.getHeader("Authorization");
        
        System.out.println("Header " + authorizationHeader);
        
        if (authorizationHeader != null && authorizationHeader.startsWith(BEARER_PREFIX)) {
            String token = authorizationHeader.substring(BEARER_PREFIX.length());
            System.out.println("Bearer Token: " + token);
            
            User theUserFromToken = jwtService.getUserFromToken(token);
            
            if (theUserFromToken != null) {
                theUser = this.theUserRepository.findById(theUserFromToken.getId())
                        .orElse(null);
            }
        }
        return theUser;
    }
}





