package com.security.mssecurity.Models;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

/**
 * DTO (Data Transfer Object) para mapear la respuesta de información
 * de usuario proporcionada por Microsoft Graph API.
 * 
 * Cuando se realiza una petición al endpoint de usuario de Microsoft Graph
 * (https://graph.microsoft.com/v1.0/me), la respuesta contiene los datos
 * del usuario autenticado en formato JSON.
 * 
 * Estructura de la respuesta de Microsoft Graph:
 * {
 *   "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
 *   "displayName": "Nombre Completo",
 *   "mail": "usuario@outlook.com",
 *   "userPrincipalName": "usuario@dominio.com",
 *   "givenName": "Nombre",
 *   "surname": "Apellido"
 * }
 * 
 * NOTA: Microsoft Graph API es el punto de acceso unificado de Microsoft
 * para obtener datos de usuarios, calendarios, correos y otros servicios.
 * El campo "mail" puede ser null en cuentas personales, en cuyo caso
 * se utiliza "userPrincipalName" como alternativa.
 * 
 * @see com.security.mssecurity.Services.MicrosoftOAuthService
 */
@Data
public class MicrosoftUserInfo {

    /**
     * Identificador único del usuario en Microsoft (formato GUID).
     * Ejemplo: "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
     */
    private String id;

    /**
     * Nombre completo para mostrar del usuario.
     * La anotación @JsonProperty asegura el mapeo correcto con el JSON de Microsoft.
     */
    @JsonProperty("displayName")
    private String displayName;

    /**
     * Dirección de correo electrónico principal del usuario.
     * Puede ser null en algunos tipos de cuentas (especialmente personales).
     */
    private String mail;

    /**
     * Nombre principal del usuario en formato de correo electrónico.
     * Formato típico: usuario@dominio.com o usuario@outlook.com
     * Se utiliza como alternativa cuando el campo "mail" es null.
     */
    @JsonProperty("userPrincipalName")
    private String userPrincipalName;

    /**
     * Nombre de pila (primer nombre) del usuario.
     */
    @JsonProperty("givenName")
    private String givenName;

    /**
     * Apellido del usuario.
     */
    private String surname;
}
