package com.security.mssecurity.Repositories;

import com.security.mssecurity.Models.Session;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

/**
 * Repositorio para acceso a datos de la colección de sesiones en MongoDB.
 * 
 * Proporciona operaciones CRUD básicas para la gestión de sesiones
 * de usuario en el sistema.
 * 
 * @see Session
 */
@Repository
public interface SessionRepository extends MongoRepository<Session, String> {
}
