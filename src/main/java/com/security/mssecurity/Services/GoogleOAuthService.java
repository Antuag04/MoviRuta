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
 * Servicio que implementa el flujo de autenticación OAuth 2.0 con Google.
 * 
 * OAuth 2.0 es un protocolo de autorización que permite a los usuarios
 * autenticarse utilizando sus cuentas de proveedores externos (en este caso Google)
 * sin compartir sus credenciales con la aplicación.
 * 
 * FLUJO DE AUTENTICACIÓN:
 * 
 * 1. El usuario solicita iniciar sesión con Google
 * 2. La aplicación redirige al usuario a la pantalla de consentimiento de Google
 * 3. El usuario autoriza el acceso y Google redirige de vuelta con un código de autorización
 * 4. La aplicación intercambia el código por un token de acceso (access_token)
 * 5. Con el access_token, se obtienen los datos del usuario desde Google
 * 6. Se crea o recupera el usuario en la base de datos local
 * 7. Se genera un JWT propio para las sesiones subsecuentes
 * 
 * Configuración requerida en Google Cloud Console:
 * - Crear un proyecto en console.cloud.google.com
 * - Habilitar la API de Google+
 * - Configurar la pantalla de consentimiento OAuth
 * - Crear credenciales OAuth 2.0 (client_id y client_secret)
 * - Registrar las URIs de redirección autorizadas
 * 
 * @see com.security.mssecurity.Controllers.GoogleOAuthController
 * @see GoogleUserInfo
 */
@Service
public class GoogleOAuthService {

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

    /**
     * Cliente HTTP reactivo para realizar peticiones a los endpoints de Google.
     */
    private final WebClient webClient = WebClient.builder().build();

    /**
     * Intercambia el código de autorización por un token de acceso.
     * 
     * Este método realiza una petición POST al endpoint de tokens de Google,
     * enviando el código de autorización junto con las credenciales de la aplicación.
     * 
     * Endpoint: https://oauth2.googleapis.com/token
     * 
     * @param code Código de autorización recibido de Google
     * @return Token de acceso (access_token) para consultar la API de Google
     */
    public String exchangeCodeForAccessToken(String code) {
        String tokenUrl = "https://oauth2.googleapis.com/token";

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("code", code);
        formData.add("client_id", clientId);
        formData.add("client_secret", clientSecret);
        formData.add("redirect_uri", redirectUri);
        formData.add("grant_type", "authorization_code");

        Map<String, Object> response = webClient.post()
                .uri(tokenUrl)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromFormData(formData))
                .retrieve()
                .bodyToMono(Map.class)
                .block();

        return (String) response.get("access_token");
    }

    /**
     * Obtiene la información del usuario desde la API de Google.
     * 
     * Realiza una petición GET al endpoint de userinfo de Google,
     * utilizando el token de acceso para autenticar la solicitud.
     * 
     * Endpoint: https://www.googleapis.com/oauth2/v3/userinfo
     * 
     * @param accessToken Token de acceso obtenido previamente
     * @return Objeto GoogleUserInfo con los datos del usuario
     */
    public GoogleUserInfo getUserInfo(String accessToken) {
        String userInfoUrl = "https://www.googleapis.com/oauth2/v3/userinfo";

        return webClient.get()
                .uri(userInfoUrl)
                .header("Authorization", "Bearer " + accessToken)
                .retrieve()
                .bodyToMono(GoogleUserInfo.class)
                .block();
    }

    /**
     * Procesa el flujo completo de autenticación con Google.
     * 
     * Este método orquesta todo el proceso de autenticación:
     * 1. Intercambia el código por un token de acceso
     * 2. Obtiene la información del usuario de Google
     * 3. Busca o crea el usuario en la base de datos local
     * 4. Asigna el rol "CIUDADANO" si es un nuevo usuario
     * 5. Genera y retorna un token JWT propio
     * 
     * @param code Código de autorización recibido de Google
     * @return Token JWT para autenticación en la aplicación
     * @throws RuntimeException Si el email ya está registrado con otro método de autenticación
     */
    public String processGoogleLogin(String code) {
        String accessToken = exchangeCodeForAccessToken(code);
        GoogleUserInfo googleUser = getUserInfo(accessToken);
        
        User existingUser = userRepository.getUserByEmail(googleUser.getEmail());
        
        if (existingUser != null) {
            if (!"GOOGLE".equals(existingUser.getAuthProvider())) {
                throw new RuntimeException(
                    "Este email ya está registrado. Por favor, inicie sesión con su contraseña."
                );
            }
            return jwtService.generateToken(existingUser);
        }
        
        User newUser = new User(
                googleUser.getName(),
                googleUser.getEmail(),
                "GOOGLE",
                true
        );
        
        User savedUser = userRepository.save(newUser);
        
        Role ciudadanoRole = roleRepository.findByName("CIUDADANO");
        if (ciudadanoRole != null) {
            UserRole userRole = new UserRole(savedUser, ciudadanoRole);
            userRoleRepository.save(userRole);
        }
        
        return jwtService.generateToken(savedUser);
    }
}
