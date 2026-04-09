package com.security.mssecurity.Controllers;

import com.security.mssecurity.Services.GitHubOAuthService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.Map;

/**
 * Controlador REST que gestiona los endpoints de autenticación OAuth 2.0 con GitHub.
 * 
 * Este controlador expone dos endpoints públicos bajo /api/public/oauth2:
 * - GET /login/github: Genera la URL de autorización de GitHub
 * - GET /callback/github: Procesa el callback de GitHub con el código de autorización
 * 
 * El flujo completo es:
 * 1. El frontend solicita la URL de login mediante GET /login/github
 * 2. El frontend redirige al usuario a esa URL
 * 3. El usuario se autentica en GitHub y autoriza la aplicación
 * 4. GitHub redirige al callback con un código de autorización
 * 5. El backend procesa el código, crea/autentica al usuario y redirige al frontend con el JWT
 * 
 * @see GitHubOAuthService
 */
@CrossOrigin
@RestController
@RequestMapping("/api/public/oauth2")
public class GitHubOAuthController {

    @Autowired
    private GitHubOAuthService gitHubOAuthService;

    @Value("${spring.security.oauth2.client.registration.github.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.github.redirect-uri}")
    private String redirectUri;

    @Value("${app.frontend.url}")
    private String frontendUrl;

    /**
     * Genera la URL de autorización de GitHub para iniciar el flujo OAuth 2.0.
     * 
     * El frontend utiliza esta URL para redirigir al usuario a la pantalla
     * de autorización de GitHub, donde autorizará el acceso a su información.
     * 
     * Parámetros incluidos en la URL:
     * - client_id: Identificador de la OAuth App en GitHub
     * - redirect_uri: URL donde GitHub enviará el código de autorización
     * - scope: Permisos solicitados (user:email para acceder al email, read:user para datos básicos)
     * 
     * @return ResponseEntity con la URL de autorización en formato JSON
     */
    @GetMapping("/login/github")
    public ResponseEntity<Map<String, String>> getGitHubLoginUrl() {
        String githubAuthUrl = "https://github.com/login/oauth/authorize"
                + "?client_id=" + clientId
                + "&redirect_uri=" + redirectUri
                + "&scope=user:email%20read:user";
        
        return ResponseEntity.ok(Map.of("url", githubAuthUrl));
    }

    /**
     * Procesa el callback de GitHub después de que el usuario autoriza la aplicación.
     * 
     * Este endpoint es invocado directamente por GitHub cuando el usuario
     * completa el proceso de autorización. Recibe un código temporal que
     * se intercambia por tokens de acceso.
     * 
     * El proceso incluye:
     * 1. Recibir el código de autorización de GitHub
     * 2. Intercambiar el código por un access_token
     * 3. Obtener la información del usuario desde la API de GitHub
     * 4. Obtener el email del endpoint adicional si es necesario
     * 5. Crear o autenticar al usuario en la base de datos local
     * 6. Generar un JWT propioend
     * 7. Redirigir al frontend con el token o mensaje de error
     * 
     * Redirección exitosa: {frontendUrl}/auth/callback?token={jwt}
     * Redirección con error: {frontendUrl}/auth/callback?error={mensaje}
     * 
     * @param code     Código de autorización proporcionado por GitHub
     * @param response HttpServletResponse para realizar la redirección
     * @throws IOException Si ocurre un error durante la redirección
     */
    @GetMapping("/callback/github")
    public void githubCallback(
            @RequestParam("code") String code,
            HttpServletResponse response) throws IOException {
        
        System.out.println("========== GITHUB CALLBACK ==========");
        System.out.println("Code recibido: " + code.substring(0, Math.min(20, code.length())) + "...");
        
        try {
            String jwtToken = gitHubOAuthService.processGitHubLogin(code);
            
            System.out.println("✅ Login con GitHub exitoso! Redirigiendo al frontend...");
            response.sendRedirect(frontendUrl + "/auth/callback?token=" + jwtToken);
            
        } catch (RuntimeException e) {
            System.out.println("❌ Error controlado: " + e.getMessage());
            response.sendRedirect(frontendUrl + "/auth/callback?error=" + e.getMessage());
                    
        } catch (Exception e) {
            System.out.println("❌ Error inesperado: " + e.getMessage());
            e.printStackTrace();
            response.sendRedirect(frontendUrl + "/auth/callback?error=Error al procesar login con GitHub");
        }
    }
}
