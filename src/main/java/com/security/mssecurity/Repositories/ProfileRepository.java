package com.security.mssecurity.Repositories;

import com.security.mssecurity.Models.Profile;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

/**
 * Repositorio para acceso a datos de la colección de perfiles en MongoDB.
 * 
 * Proporciona operaciones CRUD básicas para la gestión de perfiles
 * de usuario en el sistema.
 * 
 * @see Profile
 */
@Repository
public interface ProfileRepository extends MongoRepository<Profile, String> {
}
