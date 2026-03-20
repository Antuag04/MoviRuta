package com.security.mssecurity.Models;

import lombok.Data;

/**
 * DTO (Data Transfer Object) para mapear la respuesta de información
 * de usuario proporcionada por la API de GitHub.
 * 
 * Cuando se realiza una petición al endpoint de usuario de GitHub
 * (https://api.github.com/user), la respuesta contiene los datos
 * del usuario autenticado en formato JSON.
 * 
 * Estructura de la respuesta de GitHub:
 * {
 *   "id": 123456789,
 *   "login": "nombre_usuario",
 *   "name": "Nombre Completo",
 *   "email": "usuario@ejemplo.com",
 *   "avatar_url": "https://avatars.githubusercontent.com/..."
 * }
 * 
 * NOTA: El campo email puede ser null si el usuario tiene configurada
 * su dirección de correo como privada en GitHub. En ese caso, es
 * necesario realizar una petición adicional a /user/emails.
 * 
 * @see com.security.mssecurity.Services.GitHubOAuthService
 */
@Data
public class GitHubUserInfo {

    /**
     * Identificador numérico único del usuario en GitHub.
     */
    private Long id;

    /**
     * Nombre de usuario de GitHub (username).
     * Ejemplo: "octocat"
     */
    private String login;

    /**
     * Nombre completo del usuario.
     * Puede ser null si el usuario no ha configurado su nombre.
     */
    private String name;

    /**
     * Dirección de correo electrónico del usuario.
     * Puede ser null si el usuario tiene el email configurado como privado.
     */
    private String email;

    /**
     * URL de la imagen de avatar del usuario en GitHub.
     */
    private String avatar_url;
}
