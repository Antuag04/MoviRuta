package com.security.mssecurity.Controllers;

import com.security.mssecurity.Services.MicrosoftOAuthService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Controlador REST que gestiona los endpoints de autenticación OAuth 2.0 con Microsoft.
 * 
 * Este controlador expone dos endpoints públicos bajo /api/public/oauth2:
 * - GET /login/microsoft: Genera la URL de autorización de Microsoft
 * - GET /callback/microsoft: Procesa el callback de Microsoft con el código de autorización
 * 
 * IMPORTANTE: Microsoft utiliza Azure Active Directory (Microsoft Entra ID) como
 * plataforma de identidad. La configuración de la aplicación debe realizarse
 * en el Azure Portal (portal.azure.com).
 * 
 * El flujo completo es:
 * 1. El frontend solicita la URL de login mediante GET /login/microsoft
 * 2. El frontend redirige al usuario a esa URL
 * 3. El usuario se autentica en Microsoft y autoriza la aplicación
 * 4. Microsoft redirige al callback con un código de autorización
 * 5. El backend procesa el código, crea/autentica al usuario y redirige al frontend con el JWT
 * 
 * @see MicrosoftOAuthService
 */
@CrossOrigin
@RestController
@RequestMapping("/api/public/oauth2")
public class MicrosoftOAuthController {

    @Autowired
    private MicrosoftOAuthService microsoftOAuthService;

    /**
     * Tenant de Microsoft que determina qué cuentas pueden autenticarse.
     * Valor por defecto: "common" (acepta cuentas personales y empresariales)
     */
    @Value("${microsoft.oauth2.tenant:common}")
    private String tenant;

    @Value("${spring.security.oauth2.client.registration.microsoft.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.microsoft.redirect-uri}")
    private String redirectUri;

    @Value("${app.frontend.url}")
    private String frontendUrl;

    /**
     * Genera la URL de autorización de Microsoft para iniciar el flujo OAuth 2.0.
     * 
     * El frontend utiliza esta URL para redirigir al usuario a la pantalla
     * de consentimiento de Azure AD, donde autorizará el acceso a su información.
     * 
     * Parámetros incluidos en la URL:
     * - client_id: Identificador de la aplicación en Azure Portal
     * - redirect_uri: URL donde Microsoft enviará el código de autorización
     * - response_type: "code" para obtener un código de autorización
     * - scope: Permisos solicitados (openid, profile, email, User.Read)
     * - response_mode: "query" para recibir el código como query parameter
     * 
     * Scopes utilizados:
     * - openid: Autenticación OpenID Connect
     * - profile: Acceso al nombre del usuario
     * - email: Acceso al correo electrónico
     * - User.Read: Lectura de datos del usuario desde Microsoft Graph
     * 
     * @return ResponseEntity con la URL de autorización en formato JSON
     */
    @GetMapping("/login/microsoft")
    public ResponseEntity<Map<String, String>> getMicrosoftLoginUrl() {
        String scope = URLEncoder.encode("openid profile email User.Read", StandardCharsets.UTF_8);
        
        String microsoftAuthUrl = "https://login.microsoftonline.com/" + tenant + "/oauth2/v2.0/authorize"
                + "?client_id=" + clientId
                + "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8)
                + "&response_type=code"
                + "&scope=" + scope
                + "&response_mode=query";
        
        return ResponseEntity.ok(Map.of("url", microsoftAuthUrl));
    }

    /**
     * Procesa el callback de Microsoft después de que el usuario autoriza la aplicación.
     * 
     * Este endpoint es invocado directamente por Microsoft cuando el usuario
     * completa el proceso de autorización. Puede recibir un código de autorización
     * exitoso o un mensaje de error si el usuario cancela o hay algún problema.
     * 
     * El proceso incluye:
     * 1. Verificar si Microsoft envió un error
     * 2. Recibir el código de autorización
     * 3. Intercambiar el código por un access_token
     * 4. Obtener la información del usuario desde Microsoft Graph API
     * 5. Crear o autenticar al usuario en la base de datos local
     * 6. Generar un JWT propio
     * 7. Redirigir al frontend con el token o mensaje de error
     * 
     * Redirección exitosa: {frontendUrl}/auth/callback?token={jwt}
     * Redirección con error: {frontendUrl}/auth/callback?error={mensaje}
     * 
     * @param code             Código de autorización proporcionado por Microsoft
     * @param error            Código de error (opcional, si Microsoft reporta un error)
     * @param errorDescription Descripción del error (opcional)
     * @param response         HttpServletResponse para realizar la redirección
     * @throws IOException Si ocurre un error durante la redirección
     */
    @GetMapping("/callback/microsoft")
    public void microsoftCallback(
            @RequestParam("code") String code,
            @RequestParam(value = "error", required = false) String error,
            @RequestParam(value = "error_description", required = false) String errorDescription,
            HttpServletResponse response) throws IOException {
        
        System.out.println("========== MICROSOFT CALLBACK ==========");
        
        if (error != null) {
            System.out.println("❌ Error de Microsoft: " + error);
            System.out.println("   Descripción: " + errorDescription);
            response.sendRedirect(frontendUrl + "/auth/callback?error=" + 
                    URLEncoder.encode(errorDescription != null ? errorDescription : error, StandardCharsets.UTF_8));
            return;
        }
        
        System.out.println("Code recibido: " + code.substring(0, Math.min(20, code.length())) + "...");
        
        try {
            String jwtToken = microsoftOAuthService.processMicrosoftLogin(code);
            
            System.out.println("✅ Login con Microsoft exitoso! Redirigiendo al frontend...");
            response.sendRedirect(frontendUrl + "/auth/callback?token=" + jwtToken);
            
        } catch (RuntimeException e) {
            System.out.println("❌ Error controlado: " + e.getMessage());
            response.sendRedirect(frontendUrl + "/auth/callback?error=" + 
                    URLEncoder.encode(e.getMessage(), StandardCharsets.UTF_8));
                    
        } catch (Exception e) {
            System.out.println("❌ Error inesperado: " + e.getMessage());
            e.printStackTrace();
            response.sendRedirect(frontendUrl + "/auth/callback?error=" + 
                    URLEncoder.encode("Error al procesar login con Microsoft", StandardCharsets.UTF_8));
        }
    }
}
