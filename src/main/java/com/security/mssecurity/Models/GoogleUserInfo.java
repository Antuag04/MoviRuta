package com.security.mssecurity.Models;

import lombok.Data;

/**
 * DTO (Data Transfer Object) para recibir los datos del usuario desde Google.
 * 
 * Cuando Google nos responde, nos envía un JSON con esta estructura:
 * {
 *   "sub": "123456789",        ← ID único del usuario en Google
 *   "name": "Juan Pérez",      ← Nombre completo
 *   "email": "juan@gmail.com", ← Correo electrónico
 *   "picture": "https://..."   ← URL de la foto de perfil
 * }
 * 
 * Esta clase "mapea" ese JSON a un objeto Java.
 */
@Data
public class GoogleUserInfo {
    
    // "sub" es el ID único del usuario en Google (subject)
    private String sub;
    
    // Nombre completo del usuario
    private String name;
    
    // Correo electrónico (verificado por Google)
    private String email;
    
    // URL de la foto de perfil (opcional, por si la necesitas después)
    private String picture;
}
