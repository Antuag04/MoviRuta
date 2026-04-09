package com.security.mssecurity.Controllers;

import com.security.mssecurity.Models.User;
import com.security.mssecurity.Models.UserRole;
import com.security.mssecurity.Services.JwtService;
import com.security.mssecurity.Services.UserRoleService;
import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@CrossOrigin
@RestController
@RequestMapping("/api/user-role")
public class UserRoleController {

    @Autowired
    private UserRoleService theUserRoleService;

    @Autowired
    private JwtService jwtService;

    @GetMapping("")
    public List<UserRole> findAll() {
        return this.theUserRoleService.findAll();
    }

    @PostMapping("user/{userId}/role/{roleId}")
    public ResponseEntity<?> addUserRole(
            @PathVariable String userId,
            @PathVariable String roleId) {

        UserRole createdUserRole = this.theUserRoleService.addUserRole(userId, roleId);
        if (createdUserRole == null) {
            return ResponseEntity
                    .status(HttpStatus.NOT_FOUND)
                    .body(Map.of("message", "User or Role not found"));
        }

        return ResponseEntity.ok(createdUserRole);
    }

    @DeleteMapping("{userRoleId}")
    public ResponseEntity<Map<String, String>> removeUserRole(
            @PathVariable String userRoleId) {

        boolean response = this.theUserRoleService.removeUserRole(userRoleId);
        if (response) {
            return ResponseEntity.ok(Map.of("message", "Success"));
        } else {
            return ResponseEntity
                    .status(HttpStatus.NOT_FOUND)
                    .body(Map.of("message", "User or Role not found"));
        }
    }

    @GetMapping("/my-roles")
    public ResponseEntity<?> getMyRoles(@RequestHeader("Authorization") String authHeader) {
        try {
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "Token no proporcionado"));
            }

            String token = authHeader.replace("Bearer ", "");
            User user = jwtService.getUserFromToken(token);

            if (user == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "Token invalido o expirado"));
            }

            List<String> roles = theUserRoleService.getUserRoles(user.getId());
            return ResponseEntity.ok(Map.of("roles", roles));

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Error al obtener roles: " + e.getMessage()));
        }
    }
}
