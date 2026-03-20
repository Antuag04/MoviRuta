package com.security.mssecurity.Repositories;

import com.security.mssecurity.Models.Role;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRepository extends MongoRepository<Role, String> {
    @Query("{'name': {$regex: ?0, $options: 'i'}}")
    Role findByName(String name);
}
