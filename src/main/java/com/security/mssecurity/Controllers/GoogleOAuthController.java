package com.security.mssecurity.Controllers;

import com.security.mssecurity.Services.GoogleOAuthService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.Map;

/**
 * Controlador REST que gestiona los endpoints de autenticación OAuth 2.0 con Google.
 * 
 * Este controlador expone dos endpoints públicos bajo /api/public/oauth2:
 * - GET /login/google: Genera la URL de autorización de Google
 * - GET /callback/google: Procesa el callback de Google con el código de autorización
 * 
 * El flujo completo es:
 * 1. El frontend solicita la URL de login mediante GET /login/google
 * 2. El frontend redirige al usuario a esa URL
 * 3. El usuario se autentica en Google y autoriza la aplicación
 * 4. Google redirige al callback con un código de autorización
 * 5. El backend procesa el código, crea/autentica al usuario y redirige al frontend con el JWT
 * 
 * @see GoogleOAuthService
 */
@CrossOrigin
@RestController
@RequestMapping("/api/public/oauth2")
public class GoogleOAuthController {

    @Autowired
    private GoogleOAuthService googleOAuthService;

    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.google.redirect-uri}")
    private String redirectUri;

    @Value("${app.frontend.url}")
    private String frontendUrl;

    /**
     * Genera la URL de autorización de Google para iniciar el flujo OAuth 2.0.
     * 
     * El frontend utiliza esta URL para redirigir al usuario a la pantalla
     * de consentimiento de Google, donde autorizará el acceso a su información.
     * 
     * Parámetros incluidos en la URL:
     * - client_id: Identificador de la aplicación en Google Cloud Console
     * - redirect_uri: URL donde Google enviará el código de autorización
     * - response_type: "code" para obtener un código de autorización
     * - scope: Permisos solicitados (openid, profile, email)
     * - access_type: "offline" para obtener un refresh_token
     * 
     * @return ResponseEntity con la URL de autorización en formato JSON
     */
    @GetMapping("/login/google")
    public ResponseEntity<Map<String, String>> getGoogleLoginUrl() {
        String googleAuthUrl = "https://accounts.google.com/o/oauth2/v2/auth"
                + "?client_id=" + clientId
                + "&redirect_uri=" + redirectUri
                + "&response_type=code"
                + "&scope=openid%20profile%20email"
                + "&access_type=offline";
        
        return ResponseEntity.ok(Map.of("url", googleAuthUrl));
    }

    /**
     * Procesa el callback de Google después de que el usuario autoriza la aplicación.
     * 
     * Este endpoint es invocado directamente por Google cuando el usuario
     * completa el proceso de autorización. Recibe un código temporal que
     * se intercambia por tokens de acceso.
     * 
     * El proceso incluye:
     * 1. Recibir el código de autorización de Google
     * 2. Intercambiar el código por un access_token
     * 3. Obtener la información del usuario desde Google
     * 4. Crear o autenticar al usuario en la base de datos local
     * 5. Generar un JWT propio
     * 6. Redirigir al frontend con el token o mensaje de error
     * 
     * Redirección exitosa: {frontendUrl}/auth/callback?token={jwt}
     * Redirección con error: {frontendUrl}/auth/callback?error={mensaje}
     * 
     * @param code     Código de autorización proporcionado por Google
     * @param response HttpServletResponse para realizar la redirección
     * @throws IOException Si ocurre un error durante la redirección
     */
    @GetMapping("/callback/google")
    public void googleCallback(
            @RequestParam("code") String code,
            HttpServletResponse response) throws IOException {
        
        System.out.println("========== GOOGLE CALLBACK ==========");
        System.out.println("Code recibido: " + code.substring(0, Math.min(20, code.length())) + "...");
        
        try {
            String jwtToken = googleOAuthService.processGoogleLogin(code);
            
            System.out.println("✅ Login exitoso! Redirigiendo al frontend...");
            response.sendRedirect(frontendUrl + "/auth/callback?token=" + jwtToken);
            
        } catch (RuntimeException e) {
            System.out.println("❌ Error controlado: " + e.getMessage());
            response.sendRedirect(frontendUrl + "/auth/callback?error=" + e.getMessage());
                    
        } catch (Exception e) {
            System.out.println("❌ Error inesperado: " + e.getMessage());
            e.printStackTrace();
            response.sendRedirect(frontendUrl + "/auth/callback?error=Error al procesar login con Google");
        }
    }
}
