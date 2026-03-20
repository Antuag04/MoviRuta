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
 * Controlador que maneja los endpoints de Google OAuth 2.0
 * 
 * Este controlador tiene 2 endpoints:
 * 1. GET /login/google → Genera la URL para redirigir a Google
 * 2. GET /callback/google → Recibe el código de Google y redirige al frontend con el token
 */
@CrossOrigin
@RestController
@RequestMapping("/api/public/oauth2")
public class GoogleOAuthController {

    @Autowired
    private GoogleOAuthService googleOAuthService;

    // Valores desde application.properties
    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.google.redirect-uri}")
    private String redirectUri;

    @Value("${app.frontend.url}")
    private String frontendUrl;

    /**
     * ENDPOINT 1: Obtener la URL de login de Google
     * 
     * Tu frontend llama a este endpoint para obtener la URL a la que
     * debe redirigir al usuario.
     * 
     * Ejemplo de respuesta:
     * {
     *   "url": "https://accounts.google.com/o/oauth2/v2/auth?client_id=xxx&redirect_uri=xxx&..."
     * }
     */
    @GetMapping("/login/google")
    public ResponseEntity<Map<String, String>> getGoogleLoginUrl() {
        // Construimos la URL de autorización de Google
        String googleAuthUrl = "https://accounts.google.com/o/oauth2/v2/auth"
                + "?client_id=" + clientId
                + "&redirect_uri=" + redirectUri
                + "&response_type=code"           // Queremos un "code"
                + "&scope=openid%20profile%20email" // Permisos que pedimos
                + "&access_type=offline";          // Para obtener refresh_token
        
        return ResponseEntity.ok(Map.of("url", googleAuthUrl));
    }

    /**
     * ENDPOINT 2: Callback de Google
     * 
     * Cuando el usuario se autentica en Google, Google redirige aquí con un "code".
     * 
     * Este endpoint:
     * 1. Recibe el code
     * 2. Lo intercambia por access_token
     * 3. Obtiene los datos del usuario
     * 4. Crea o busca el usuario en la BD
     * 5. REDIRIGE AL FRONTEND con el token en la URL
     * 
     * El frontend recibirá: http://localhost:4200/auth/callback?token=eyJhbG...
     */
    @GetMapping("/callback/google")
    public void googleCallback(
            @RequestParam("code") String code,
            HttpServletResponse response) throws IOException {
        
        System.out.println("========== GOOGLE CALLBACK ==========");
        System.out.println("Code recibido: " + code.substring(0, Math.min(20, code.length())) + "...");
        
        try {
            // Procesamos todo el flujo OAuth y obtenemos nuestro JWT
            String jwtToken = googleOAuthService.processGoogleLogin(code);
            
            System.out.println("✅ Login exitoso! Redirigiendo al frontend...");
            
            // REDIRIGIR AL FRONTEND con el token en la URL
            // El frontend capturará este token y lo guardará
            response.sendRedirect(frontendUrl + "/auth/callback?token=" + jwtToken);
            
        } catch (RuntimeException e) {
            // Error controlado (ej: email ya existe con otro método)
            System.out.println("❌ Error controlado: " + e.getMessage());
            response.sendRedirect(frontendUrl + "/auth/callback?error=" + e.getMessage());
                    
        } catch (Exception e) {
            // Error inesperado
            System.out.println("❌ Error inesperado: " + e.getMessage());
            e.printStackTrace();
            response.sendRedirect(frontendUrl + "/auth/callback?error=Error al procesar login con Google");
        }
    }
}
