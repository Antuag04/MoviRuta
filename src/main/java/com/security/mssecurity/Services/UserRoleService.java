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
public class UserRoleService {
    @Autowired
    private UserRepository theUserRepository;

    @Autowired
    private RoleRepository theRoleRepository;

    @Autowired
    private UserRoleRepository theUserRoleRepository;

    public boolean addUserRole(String userId,
                               String roleId) {
        User user = this.theUserRepository.findById(userId).orElse(null);
        Role role = this.theRoleRepository.findById(roleId).orElse(null);
        if (user != null && role != null) {
            UserRole theUserRole = new UserRole(user, role);
            this.theUserRoleRepository.save(theUserRole);
            return true;
        } else {
            return false;
        }
    }

    public boolean removeUserRole(String userRoleId){
        UserRole userRole=this.theUserRoleRepository.findById(userRoleId).orElse(null);
        if (userRole!=null){
            this.theUserRoleRepository.delete(userRole);
            return true;
        }else{
            return false;
        }
    }

}

