package com.security.mssecurity.Services;

import com.security.mssecurity.Models.GoogleUserInfo;
import com.security.mssecurity.Models.Role;
import com.security.mssecurity.Models.User;
import com.security.mssecurity.Models.UserRole;
import com.security.mssecurity.Repositories.RoleRepository;
import com.security.mssecurity.Repositories.UserRepository;
import com.security.mssecurity.Repositories.UserRoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.Map;

/**
 * Servicio que maneja toda la lógica de autenticación con Google OAuth 2.0
 * 
 * FLUJO COMPLETO:
 * 1. El usuario hace clic en "Iniciar sesión con Google"
 * 2. Google le muestra pantalla de permisos
 * 3. Google redirige a tu app con un CODE
 * 4. Este servicio intercambia el CODE por un ACCESS_TOKEN
 * 5. Con el ACCESS_TOKEN, obtenemos los datos del usuario (nombre, email)
 * 6. Creamos o buscamos el usuario en nuestra BD
 * 7. Generamos nuestro propio JWT
 */
@Service
public class GoogleOAuthService {

    // Inyectamos los valores desde application.properties
    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.google.client-secret}")
    private String clientSecret;

    @Value("${spring.security.oauth2.client.registration.google.redirect-uri}")
    private String redirectUri;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private UserRoleRepository userRoleRepository;

    // WebClient es como un "navegador programático" para hacer peticiones HTTP
    private final WebClient webClient = WebClient.builder().build();

    /**
     * PASO 1: Intercambiar el CODE por un ACCESS_TOKEN
     * 
     * Google nos dio un "code" temporal. Ahora debemos cambiarlo por un
     * "access_token" que nos permite acceder a los datos del usuario.
     * 
     * Es como: el CODE es un ticket, el ACCESS_TOKEN es la entrada real.
     */
    public String exchangeCodeForAccessToken(String code) {
        // URL de Google para intercambiar códigos por tokens
        String tokenUrl = "https://oauth2.googleapis.com/token";

        // Preparamos los datos que Google requiere
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("code", code);                      // El código que Google nos dio
        formData.add("client_id", clientId);             // Tu ID de aplicación
        formData.add("client_secret", clientSecret);     // Tu secreto (nunca compartir!)
        formData.add("redirect_uri", redirectUri);       // Debe coincidir con Google Console
        formData.add("grant_type", "authorization_code"); // Tipo de flujo OAuth

        // Hacemos la petición POST a Google
        Map<String, Object> response = webClient.post()
                .uri(tokenUrl)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromFormData(formData))
                .retrieve()
                .bodyToMono(Map.class)  // Convertimos la respuesta a un Map
                .block();               // Esperamos la respuesta (síncrono)

        // Google nos responde con algo como:
        // { "access_token": "ya29.xxx...", "expires_in": 3600, ... }
        return (String) response.get("access_token");
    }

    /**
     * PASO 2: Obtener la información del usuario desde Google
     * 
     * Con el ACCESS_TOKEN, podemos preguntarle a Google:
     * "¿Quién es este usuario?"
     */
    public GoogleUserInfo getUserInfo(String accessToken) {
        // URL de Google para obtener info del usuario
        String userInfoUrl = "https://www.googleapis.com/oauth2/v3/userinfo";

        // Hacemos GET con el token en el header Authorization
        return webClient.get()
                .uri(userInfoUrl)
                .header("Authorization", "Bearer " + accessToken)  // El token va aquí
                .retrieve()
                .bodyToMono(GoogleUserInfo.class)  // Convertimos a nuestro DTO
                .block();
    }

    /**
     * PASO 3: Procesar el login/registro con Google
     * 
     * Este es el método principal que une todo:
     * - Si el usuario ya existe → lo buscamos y generamos JWT
     * - Si es nuevo → lo creamos y generamos JWT
     */
    public String processGoogleLogin(String code) {
        // PASO 1: Intercambiar code por access_token
        String accessToken = exchangeCodeForAccessToken(code);
        
        // PASO 2: Obtener datos del usuario de Google
        GoogleUserInfo googleUser = getUserInfo(accessToken);
        
        // PASO 3: Buscar si el usuario ya existe en nuestra BD
        User existingUser = userRepository.getUserByEmail(googleUser.getEmail());
        
        if (existingUser != null) {
            // El usuario YA existe
            
            // Verificamos que sea un usuario de Google (no de registro local)
            if (!"GOOGLE".equals(existingUser.getAuthProvider())) {
                // El email existe pero se registró con contraseña
                throw new RuntimeException(
                    "Este email ya está registrado. Por favor, inicia sesión con tu contraseña."
                );
            }
            
            // Es usuario de Google, generamos su JWT
            return jwtService.generateToken(existingUser);
        }
        
        // PASO 4: El usuario NO existe, lo creamos
        User newUser = new User(
                googleUser.getName(),   // Nombre de Google
                googleUser.getEmail(),  // Email de Google
                "GOOGLE",               // authProvider = GOOGLE
                true                    // Flag para usar el constructor OAuth
        );
        
        // Guardamos el nuevo usuario
        User savedUser = userRepository.save(newUser);
        
        // PASO 5: Asignar rol "CIUDADANO" (igual que en registro normal)
        Role ciudadanoRole = roleRepository.findByName("CIUDADANO");
        if (ciudadanoRole != null) {
            UserRole userRole = new UserRole(savedUser, ciudadanoRole);
            userRoleRepository.save(userRole);
        }
        
        // PASO 6: Generar y retornar el JWT
        return jwtService.generateToken(savedUser);
    }
}
