package com.security.mssecurity.Repositories;

import com.security.mssecurity.Models.User;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;

/**
 * Repositorio para acceso a datos de la colección de usuarios en MongoDB.
 * 
 * Extiende MongoRepository para proporcionar operaciones CRUD básicas
 * y define consultas personalizadas para búsquedas específicas.
 * 
 * @see User
 */
@Repository
public interface UserRepository extends MongoRepository<User, String> {
    
    /**
     * Busca un usuario por su dirección de correo electrónico.
     * 
     * Esta consulta es utilizada para:
     * - Validar credenciales durante el login
     * - Verificar duplicados durante el registro
     * - Buscar usuarios existentes en flujos OAuth
     * 
     * @param email Correo electrónico a buscar
     * @return Usuario encontrado o null si no existe
     */
    @Query("{'email': ?0}")
    public User getUserByEmail(String email);
}
