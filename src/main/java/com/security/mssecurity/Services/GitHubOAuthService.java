package com.security.mssecurity.Services;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.mssecurity.Models.GitHubUserInfo;
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
import java.util.List;
import java.util.Map;

/**
 * Servicio que implementa el flujo de autenticación OAuth 2.0 con GitHub.
 * 
 * OAuth 2.0 es un protocolo de autorización que permite a los usuarios
 * autenticarse utilizando sus cuentas de proveedores externos (en este caso GitHub)
 * sin compartir sus credenciales con la aplicación.
 * 
 * FLUJO DE AUTENTICACIÓN:
 * 
 * 1. El usuario solicita iniciar sesión con GitHub
 * 2. La aplicación redirige al usuario a la pantalla de autorización de GitHub
 * 3. El usuario autoriza el acceso y GitHub redirige de vuelta con un código
 * 4. La aplicación intercambia el código por un token de acceso
 * 5. Con el token, se obtienen los datos del usuario desde la API de GitHub
 * 6. Se crea o recupera el usuario en la base de datos local
 * 7. Se genera un JWT propio para las sesiones subsecuentes
 * 
 * CONSIDERACIÓN ESPECIAL:
 * GitHub puede tener el email configurado como privado, en cuyo caso es
 * necesario realizar una petición adicional al endpoint /user/emails
 * para obtener el correo electrónico del usuario.
 * 
 * Configuración requerida en GitHub:
 * - Acceder a Settings > Developer settings > OAuth Apps
 * - Crear una nueva OAuth App con la URL de callback correcta
 * - Obtener el Client ID y generar un Client Secret
 * 
 * @see com.security.mssecurity.Controllers.GitHubOAuthController
 * @see GitHubUserInfo
 */
@Service
public class GitHubOAuthService {

    @Value("${spring.security.oauth2.client.registration.github.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.github.client-secret}")
    private String clientSecret;

    @Value("${spring.security.oauth2.client.registration.github.redirect-uri}")
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
     * Cliente HTTP reactivo para realizar peticiones a los endpoints de GitHub.
     */
    private final WebClient webClient = WebClient.builder().build();

    /**
     * Intercambia el código de autorización por un token de acceso.
     * 
     * Este método realiza una petición POST al endpoint de tokens de GitHub.
     * Es importante incluir el header "Accept: application/json" para recibir
     * la respuesta en formato JSON.
     * 
     * Endpoint: https://github.com/login/oauth/access_token
     * 
     * @param code Código de autorización recibido de GitHub
     * @return Token de acceso para consultar la API de GitHub
     */
    public String exchangeCodeForAccessToken(String code) {
        String tokenUrl = "https://github.com/login/oauth/access_token";

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("code", code);
        formData.add("client_id", clientId);
        formData.add("client_secret", clientSecret);
        formData.add("redirect_uri", redirectUri);

        Map<String, Object> response = webClient.post()
                .uri(tokenUrl)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header("Accept", "application/json")
                .body(BodyInserters.fromFormData(formData))
                .retrieve()
                .bodyToMono(Map.class)
                .block();

        return (String) response.get("access_token");
    }

    /**
     * Obtiene la información básica del usuario desde la API de GitHub.
     * 
     * Endpoint: https://api.github.com/user
     * 
     * NOTA: El campo email puede ser null si el usuario tiene configurada
     * su dirección de correo como privada.
     * 
     * @param accessToken Token de acceso obtenido previamente
     * @return Objeto GitHubUserInfo con los datos del usuario
     */
    public GitHubUserInfo getUserInfo(String accessToken) {
        String userInfoUrl = "https://api.github.com/user";

        return webClient.get()
                .uri(userInfoUrl)
                .header("Authorization", "Bearer " + accessToken)
                .header("Accept", "application/json")
                .retrieve()
                .bodyToMono(GitHubUserInfo.class)
                .block();
    }

    /**
     * Obtiene el email del usuario cuando está configurado como privado.
     * 
     * Este método consulta el endpoint de emails de GitHub para obtener
     * el correo electrónico primario y verificado del usuario.
     * 
     * Endpoint: https://api.github.com/user/emails
     * 
     * La prioridad de selección es:
     * 1. Email primario y verificado
     * 2. Cualquier email verificado
     * 
     * @param accessToken Token de acceso obtenido previamente
     * @return Email del usuario, o null si no se encuentra uno válido
     */
    public String getUserEmail(String accessToken) {
        String emailsUrl = "https://api.github.com/user/emails";

        List<Map<String, Object>> emails = webClient.get()
                .uri(emailsUrl)
                .header("Authorization", "Bearer " + accessToken)
                .header("Accept", "application/json")
                .retrieve()
                .bodyToMono(List.class)
                .block();

        if (emails != null) {
            for (Map<String, Object> email : emails) {
                Boolean primary = (Boolean) email.get("primary");
                Boolean verified = (Boolean) email.get("verified");
                if (Boolean.TRUE.equals(primary) && Boolean.TRUE.equals(verified)) {
                    return (String) email.get("email");
                }
            }
            for (Map<String, Object> email : emails) {
                Boolean verified = (Boolean) email.get("verified");
                if (Boolean.TRUE.equals(verified)) {
                    return (String) email.get("email");
                }
            }
        }
        return null;
    }

    /**
     * Procesa el flujo completo de autenticación con GitHub.
     * 
     * Este método orquesta todo el proceso de autenticación:
     * 1. Intercambia el código por un token de acceso
     * 2. Obtiene la información del usuario de GitHub
     * 3. Obtiene el email (del endpoint adicional si es necesario)
     * 4. Busca o crea el usuario en la base de datos local
     * 5. Asigna el rol "CIUDADANO" si es un nuevo usuario
     * 6. Genera y retorna un token JWT propio
     * 
     * Si no se puede obtener el email por ningún medio, se genera uno
     * con el formato: {username}@github.local
     * 
     * @param code Código de autorización recibido de GitHub
     * @return Token JWT para autenticación en la aplicación
     * @throws RuntimeException Si el email ya está registrado con otro método de autenticación
     */
    public String processGitHubLogin(String code) {
        String accessToken = exchangeCodeForAccessToken(code);
        GitHubUserInfo githubUser = getUserInfo(accessToken);
        
        String email = githubUser.getEmail();
        if (email == null || email.isEmpty()) {
            email = getUserEmail(accessToken);
        }
        
        if (email == null || email.isEmpty()) {
            email = githubUser.getLogin() + "@github.local";
        }
        
        User existingUser = userRepository.getUserByEmail(email);
        
        if (existingUser != null) {
            // Usuario existente - ya se registró previamente con GitHub
            if (!"GITHUB".equals(existingUser.getAuthProvider())) {
                throw new RuntimeException(
                    "Este email ya está registrado. Por favor, inicie sesión con su método original."
                );
            }
            
            // Generar JWT para usuario existente
            String jwtToken = jwtService.generateToken(existingUser);
            
            // Crear sesión para rastrear este login
            createSession(existingUser, jwtToken);
            
            return jwtToken;
        }
        
        String userName = githubUser.getName();
        if (userName == null || userName.isEmpty()) {
            userName = githubUser.getLogin();
        }
        
        User newUser = new User(
                userName,
                email,
                "GITHUB",
                true
        );
        
        User savedUser = userRepository.save(newUser);
        
        Role ciudadanoRole = roleRepository.findByName("CIUDADANO");
        if (ciudadanoRole != null) {
            UserRole userRole = new UserRole(savedUser, ciudadanoRole);
            userRoleRepository.save(userRole);
        }
        
        // Crear perfil con avatar de GitHub
        // GitHub proporciona avatar_url con la foto del usuario
        createProfileWithPhoto(savedUser, githubUser.getAvatar_url());
        
        // Generar JWT para usuario nuevo
        String jwtToken = jwtService.generateToken(savedUser);
        
        // Crear sesión para este primer login
        createSession(savedUser, jwtToken);
        
        return jwtToken;
    }
    
    /**
     * Crea y persiste una nueva sesión para un usuario autenticado con GitHub.
     * 
     * Funcionalidad idéntica a Google OAuth, pero para usuarios de GitHub.
     * Registra cada inicio de sesión para rastreo y gestión multi-dispositivo.
     * 
     * @param user Usuario que acaba de autenticarse
     * @param token Token JWT generado para este inicio de sesión
     * @return Session creada y persistida en MongoDB
     * @see GoogleOAuthService#createSession(User, String)
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
     * Crea y persiste un perfil con foto para un usuario OAuth de GitHub.
     * 
     * GitHub proporciona información del usuario incluyendo su avatar.
     * Este método aprovecha esa información para crear un perfil completo.
     * 
     * Datos de GitHub utilizados:
     * - avatar_url: URL del avatar del usuario en GitHub
     *   (ejemplo: "https://avatars.githubusercontent.com/u/123456?v=4")
     * 
     * Consideraciones de GitHub:
     * - El avatar es público y accesible
     * - GitHub permite avatares personalizados o Gravatar
     * - La URL incluye parámetro ?v=4 para el tamaño
     * 
     * @param user Usuario propietario del perfil
     * @param photoUrl URL del avatar proporcionada por GitHub
     * @return Profile creado y persistido en MongoDB
     */
    private Profile createProfileWithPhoto(User user, String photoUrl) {
        Profile profile = new Profile(null, photoUrl);
        profile.setUser(user);
        return profileRepository.save(profile);
    }
}
