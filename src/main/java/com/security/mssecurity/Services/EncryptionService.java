package com.security.mssecurity.Services;

import org.springframework.stereotype.Service;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * Servicio responsable de la encriptación y verificación de contraseñas.
 * 
 * Utiliza el algoritmo BCrypt, que es un algoritmo de hashing diseñado
 * específicamente para contraseñas. Sus principales características son:
 * 
 * - Incorpora un "salt" automático para prevenir ataques de tabla rainbow
 * - Es computacionalmente costoso, lo que dificulta ataques de fuerza bruta
 * - El factor de trabajo es configurable para adaptarse al hardware disponible
 * 
 * Las contraseñas nunca se almacenan en texto plano; solo se guarda el hash
 * resultante de aplicar BCrypt.
 * 
 * @see com.security.mssecurity.Services.SecurityService
 * @see com.security.mssecurity.Services.UserService
 */
@Service
public class EncryptionService {

    /**
     * Instancia del encoder BCrypt con la configuración por defecto.
     * El factor de trabajo predeterminado es 10.
     */
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    /**
     * Encripta una contraseña en texto plano utilizando BCrypt.
     * 
     * El resultado incluye el salt y el hash, permitiendo la verificación
     * posterior sin necesidad de almacenar el salt por separado.
     * 
     * @param password Contraseña en texto plano a encriptar
     * @return Hash BCrypt de la contraseña
     */
    public String encryptPassword(String password) {
        return encoder.encode(password);
    }

    /**
     * Verifica si una contraseña en texto plano coincide con un hash almacenado.
     * 
     * Extrae el salt del hash almacenado y aplica el mismo proceso de hashing
     * a la contraseña proporcionada para compararlas de forma segura.
     * 
     * @param rawPassword     Contraseña en texto plano a verificar
     * @param encodedPassword Hash BCrypt almacenado previamente
     * @return true si la contraseña coincide, false en caso contrario
     */
    public boolean verifyPassword(String rawPassword, String encodedPassword) {
        return encoder.matches(rawPassword, encodedPassword);
    }
}