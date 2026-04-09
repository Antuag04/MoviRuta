package com.security.mssecurity.Services;

import com.security.mssecurity.Models.Permission;
import com.security.mssecurity.Models.Role;
import com.security.mssecurity.Models.RolePermission;
import com.security.mssecurity.Models.User;
import com.security.mssecurity.Models.UserRole;
import com.security.mssecurity.Repositories.PermissionRepository;
import com.security.mssecurity.Repositories.RolePermissionRepository;
import com.security.mssecurity.Repositories.UserRoleRepository;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

@Service
public class ValidatorsService {

    private static final String BEARER_PREFIX = "Bearer ";

    @Autowired
    private JwtService jwtService;

    @Autowired
    private PermissionRepository thePermissionRepository;

    @Autowired
    private RolePermissionRepository theRolePermissionRepository;

    @Autowired
    private UserRoleRepository theUserRoleRepository;

    public SecurityValidationResult validationRolePermission(HttpServletRequest request,
                                                             String url,
                                                             String method) {
        User theUser = this.getUser(request);
        if (theUser == null) {
            return SecurityValidationResult.denied(
                    HttpStatus.UNAUTHORIZED.value(),
                    "Token no proporcionado o inválido"
            );
        }

        String normalizedUrl = normalizeUrl(url);
        Permission thePermission = this.thePermissionRepository.getPermission(normalizedUrl, method);
        if (thePermission == null) {
            return SecurityValidationResult.denied(
                    HttpStatus.FORBIDDEN.value(),
                    "No existe permiso configurado para este recurso"
            );
        }

        List<UserRole> roles = this.theUserRoleRepository.getRolesByUser(theUser.getId());
        for (UserRole actual : roles) {
            Role theRole = actual.getRole();
            if (theRole == null) {
                continue;
            }

            RolePermission theRolePermission = this.theRolePermissionRepository
                    .getRolePermission(theRole.getId(), thePermission.getId());

            if (theRolePermission != null) {
                return SecurityValidationResult.allowed(theUser);
            }
        }

        return SecurityValidationResult.denied(
                HttpStatus.FORBIDDEN.value(),
                "No tiene permisos para acceder a este recurso"
        );
    }

    public User getUser(final HttpServletRequest request) {
        String authorizationHeader = request.getHeader("Authorization");

        if (authorizationHeader != null && authorizationHeader.startsWith(BEARER_PREFIX)) {
            String token = authorizationHeader.substring(BEARER_PREFIX.length());
            return jwtService.getUserFromToken(token);
        }
        return null;
    }

    private String normalizeUrl(String url) {
        return url.replaceAll("[0-9a-fA-F]{24}|\\d+", "?");
    }
}
