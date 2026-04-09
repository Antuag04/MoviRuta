package com.security.mssecurity.Services;

import com.security.mssecurity.Models.Role;
import com.security.mssecurity.Models.User;
import com.security.mssecurity.Models.UserRole;
import com.security.mssecurity.Repositories.RoleRepository;
import com.security.mssecurity.Repositories.UserRepository;
import com.security.mssecurity.Repositories.UserRoleRepository;
import java.util.List;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserRoleService {

    private static final Logger logger = LoggerFactory.getLogger(UserRoleService.class);

    @Autowired
    private UserRepository theUserRepository;

    @Autowired
    private RoleRepository theRoleRepository;

    @Autowired
    private UserRoleRepository theUserRoleRepository;

    @Autowired
    private EmailService emailService;

    public UserRole addUserRole(String userId, String roleId) {
        User user = this.theUserRepository.findById(userId).orElse(null);
        Role role = this.theRoleRepository.findById(roleId).orElse(null);

        if (user == null || role == null) {
            return null;
        }

        UserRole existingUserRole = theUserRoleRepository.getUserRole(userId, roleId);
        if (existingUserRole != null) {
            return existingUserRole;
        }

        UserRole savedUserRole = this.theUserRoleRepository.save(new UserRole(user, role));
        sendRoleChangeNotificationSafely(
                user.getEmail(),
                user.getName(),
                "Se te asigno el rol " + role.getName() + "."
        );
        return savedUserRole;
    }

    public boolean removeUserRole(String userRoleId) {
        UserRole userRole = this.theUserRoleRepository.findById(userRoleId).orElse(null);

        if (userRole == null) {
            return false;
        }

        this.theUserRoleRepository.delete(userRole);
        if (userRole.getUser() != null && userRole.getRole() != null) {
            sendRoleChangeNotificationSafely(
                    userRole.getUser().getEmail(),
                    userRole.getUser().getName(),
                    "Se removio el rol " + userRole.getRole().getName() + " de tu cuenta."
            );
        }
        return true;
    }

    public List<String> getUserRoles(String userId) {
        List<UserRole> userRoles = this.theUserRoleRepository.getRolesByUser(userId);
        return userRoles.stream()
                .map(ur -> ur.getRole().getName())
                .collect(Collectors.toList());
    }

    public List<UserRole> getUserRoleDetails(String userId) {
        return this.theUserRoleRepository.getRolesByUser(userId);
    }

    public List<UserRole> findAll() {
        return this.theUserRoleRepository.findAll();
    }

    private void sendRoleChangeNotificationSafely(String toEmail, String userName, String details) {
        try {
            emailService.sendRoleChangeNotification(toEmail, userName, details);
        } catch (Exception ex) {
            logger.warn(
                    "No se pudo enviar notificacion de cambio de rol a {}. La operacion principal ya fue ejecutada.",
                    toEmail,
                    ex
            );
        }
    }
}
