package com.security.mssecurity.Services;

import com.security.mssecurity.Models.GoogleUserInfo;
import com.security.mssecurity.Models.Profile;
import com.security.mssecurity.Models.Role;
import com.security.mssecurity.Models.Session;
import com.security.mssecurity.Models.User;
import com.security.mssecurity.Models.UserRole;
import com.security.mssecurity.Repositories.ProfileRepository;
import com.security.mssecurity.Repositories.RoleRepository;
import com.security.mssecurity.Repositories.SessionRepository;
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

import java.util.Date;
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

    @Autowired
    private SessionRepository sessionRepository;

    @Autowired
    private ProfileRepository profileRepository;

    /**
     * Tiempo de expiración del token JWT en milisegundos.
     */
    @Value("${jwt.expiration}")
    private Long jwtExpiration;

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
            // Usuario existente - ya se registró previamente con Google
            if (!"GOOGLE".equals(existingUser.getAuthProvider())) {
                throw new RuntimeException(
                    "Este email ya está registrado. Por favor, inicie sesión con su contraseña."
                );
            }
            
            // Generar JWT para usuario existente
            String jwtToken = jwtService.generateToken(existingUser);
            
            // Crear sesión para rastrear este login
            // Permite al usuario ver sus sesiones activas y cerrarlas si es necesario
            createSession(existingUser, jwtToken);
            
            return jwtToken;
        }
        
        // Usuario nuevo - primer login con Google
        User newUser = new User(
                googleUser.getName(),
                googleUser.getEmail(),
                "GOOGLE",
                true
        );
        
        User savedUser = userRepository.save(newUser);
        
        // Asignar rol CIUDADANO por defecto
        Role ciudadanoRole = roleRepository.findByName("CIUDADANO");
        if (ciudadanoRole != null) {
            UserRole userRole = new UserRole(savedUser, ciudadanoRole);
            userRoleRepository.save(userRole);
        }
        
        // Crear perfil con foto de Google
        // Google proporciona una foto de alta calidad en el campo 'picture'
        // que podemos usar como foto de perfil predeterminada
        createProfileWithPhoto(savedUser, googleUser.getPicture());
        
        // Generar JWT para usuario nuevo
        String jwtToken = jwtService.generateToken(savedUser);
        
        // Crear sesión para este primer login
        createSession(savedUser, jwtToken);
        
        return jwtToken;
    }
    
    /**
     * Crea y persiste una nueva sesión para un usuario autenticado con Google.
     * 
     * Este método registra cada inicio de sesión exitoso en la base de datos,
     * vinculando el token JWT generado con el usuario. Esto permite:
     * 
     * - Rastrear todas las sesiones activas del usuario en diferentes dispositivos
     * - Implementar "Ver dispositivos conectados" en el perfil del usuario
     * - Cerrar sesiones remotamente (ej: "Cerrar sesión en todos los dispositivos")
     * - Detectar actividad sospechosa (múltiples logins simultáneos de ubicaciones diferentes)
     * - Auditar accesos al sistema para análisis de seguridad
     * 
     * La sesión creada incluye:
     * - Token JWT: El token generado para esta autenticación
     * - Expiración: Calculada según la configuración de jwt.expiration
     * - Usuario: Referencia al usuario propietario (relación @DBRef en MongoDB)
     * 
     * NOTA: Las sesiones de OAuth no utilizan el campo code2FA (es null)
     * ya que el proveedor OAuth (Google) ya realizó la autenticación.
     * 
     * @param user Usuario que acaba de autenticarse
     * @param token Token JWT generado para este inicio de sesión
     * @return Session creada y persistida en MongoDB
     */
    private Session createSession(User user, String token) {
        Session session = new Session(
            token,
            new Date(System.currentTimeMillis() + jwtExpiration),
            null
        );
        session.setUser(user);
        return sessionRepository.save(session);
    }
    
    /**
     * Crea y persiste un perfil con foto para un usuario OAuth de Google.
     * 
     * Google proporciona información rica del usuario a través de su API,
     * incluyendo una foto de perfil de alta calidad. Este método aprovecha
     * esa información para crear un perfil más completo desde el inicio.
     * 
     * Datos de Google utilizados:
     * - picture: URL de la foto de perfil del usuario en Google
     *   (ejemplo: "https://lh3.googleusercontent.com/...")
     * 
     * Beneficios de usar la foto de Google:
     * - Usuario tiene foto de perfil desde el primer login
     * - Mejora la experiencia visual de la aplicación
     * - Mantiene consistencia con la identidad del usuario en Google
     * - Evita que el usuario tenga que configurar una foto manualmente
     * 
     * IMPORTANTE: La URL es externa (alojada en servidores de Google).
     * Consideraciones:
     * - La foto puede cambiar si el usuario la actualiza en Google
     * - Requiere conexión a internet para cargar la imagen
     * - Si quieres alojarla localmente, debes descargar y subir a tu storage
     * 
     * El campo phone se deja null porque Google no comparte el número
     * de teléfono del usuario por defecto (requiere permisos especiales).
     * 
     * @param user Usuario propietario del perfil
     * @param photoUrl URL de la foto de perfil proporcionada por Google
     * @return Profile creado y persistido en MongoDB
     */
    private Profile createProfileWithPhoto(User user, String photoUrl) {
        Profile profile = new Profile(null, photoUrl);
        profile.setUser(user);
        return profileRepository.save(profile);
    }
}
