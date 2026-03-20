package com.security.mssecurity.Models;

import lombok.Data;

/**
 * DTO (Data Transfer Object) para mapear la respuesta de información
 * de usuario proporcionada por la API de Google OAuth 2.0.
 * 
 * Cuando se realiza una petición al endpoint de userinfo de Google
 * (https://www.googleapis.com/oauth2/v3/userinfo), la respuesta
 * contiene los datos del usuario autenticado en formato JSON.
 * 
 * Estructura de la respuesta de Google:
 * {
 *   "sub": "123456789012345678901",
 *   "name": "Nombre Completo",
 *   "email": "usuario@gmail.com",
 *   "picture": "https://lh3.googleusercontent.com/..."
 * }
 * 
 * @see com.security.mssecurity.Services.GoogleOAuthService
 */
@Data
public class GoogleUserInfo {

    /**
     * Identificador único del usuario en Google (Subject Identifier).
     * Es un valor numérico representado como String que identifica
     * de manera única al usuario dentro del sistema de Google.
     */
    private String sub;

    /**
     * Nombre completo del usuario tal como aparece en su cuenta de Google.
     */
    private String name;

    /**
     * Dirección de correo electrónico verificada por Google.
     * Se utiliza como identificador único del usuario en el sistema.
     */
    private String email;

    /**
     * URL de la fotografía de perfil del usuario en Google.
     * Puede utilizarse para mostrar el avatar del usuario en la aplicación.
     */
    private String picture;
}
