package com.security.mssecurity.Services;

import com.security.mssecurity.Models.MicrosoftUserInfo;
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
 * Servicio que implementa el flujo de autenticación OAuth 2.0 con Microsoft.
 * 
 * Microsoft utiliza Azure Active Directory (ahora Microsoft Entra ID) como su
 * plataforma de identidad. A diferencia de Google y GitHub, Microsoft requiere
 * configuración adicional del proveedor en application.properties ya que no es
 * un proveedor incorporado en Spring Security.
 * 
 * FLUJO DE AUTENTICACIÓN:
 * 
 * 1. El usuario solicita iniciar sesión con Microsoft
 * 2. La aplicación redirige al usuario a la pantalla de consentimiento de Azure AD
 * 3. El usuario autoriza el acceso y Microsoft redirige de vuelta con un código
 * 4. La aplicación intercambia el código por un token de acceso
 * 5. Con el token, se obtienen los datos del usuario desde Microsoft Graph API
 * 6. Se crea o recupera el usuario en la base de datos local
 * 7. Se genera un JWT propio para las sesiones subsecuentes
 * 
 * CONCEPTO DE TENANT:
 * El "tenant" determina qué tipos de cuentas pueden autenticarse:
 * - "common": Permite cuentas personales (Outlook/Hotmail) y empresariales
 * - "organizations": Solo cuentas empresariales (Azure AD)
 * - "consumers": Solo cuentas personales (Microsoft Account)
 * - {tenant-id}: Solo cuentas de un tenant específico
 * 
 * MICROSOFT GRAPH API:
 * A diferencia de otros proveedores, la información del usuario se obtiene
 * de Microsoft Graph API (graph.microsoft.com), que es el punto de acceso
 * unificado de Microsoft para datos de usuarios, calendarios, emails, etc.
 * 
 * Configuración requerida en Azure Portal:
 * - Acceder a portal.azure.com
 * - Registrar una aplicación en Azure Active Directory
 * - Configurar los permisos de API (User.Read)
 * - Crear un Client Secret y guardar el Value (no el ID)
 * - Configurar las URIs de redirección
 * 
 * @see com.security.mssecurity.Controllers.MicrosoftOAuthController
 * @see MicrosoftUserInfo
 */
@Service
public class MicrosoftOAuthService {

    /**
     * Tenant de Microsoft que determina qué cuentas pueden autenticarse.
     * Valor por defecto: "common" (acepta cuentas personales y empresariales)
     */
    @Value("${microsoft.oauth2.tenant:common}")
    private String tenant;

    @Value("${spring.security.oauth2.client.registration.microsoft.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.microsoft.client-secret}")
    private String clientSecret;

    @Value("${spring.security.oauth2.client.registration.microsoft.redirect-uri}")
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
     * Cliente HTTP reactivo para realizar peticiones a los endpoints de Microsoft.
     */
    private final WebClient webClient = WebClient.builder().build();

    /**
     * Intercambia el código de autorización por un token de acceso.
     * 
     * Este método realiza una petición POST al endpoint de tokens de Microsoft,
     * que incluye el tenant en la URL.
     * 
     * Endpoint: https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
     * 
     * @param code Código de autorización recibido de Microsoft
     * @return Token de acceso para consultar Microsoft Graph API
     */
    public String exchangeCodeForAccessToken(String code) {
        String tokenUrl = "https://login.microsoftonline.com/" + tenant + "/oauth2/v2.0/token";

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("client_id", clientId);
        formData.add("client_secret", clientSecret);
        formData.add("code", code);
        formData.add("redirect_uri", redirectUri);
        formData.add("grant_type", "authorization_code");
        formData.add("scope", "openid profile email User.Read");

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
     * Obtiene la información del usuario desde Microsoft Graph API.
     * 
     * Microsoft Graph es el API unificado de Microsoft para acceder a datos
     * de usuarios, calendarios, correos electrónicos, OneDrive y más.
     * 
     * Endpoint: https://graph.microsoft.com/v1.0/me
     * 
     * @param accessToken Token de acceso obtenido previamente
     * @return Objeto MicrosoftUserInfo con los datos del usuario
     */
    public MicrosoftUserInfo getUserInfo(String accessToken) {
        String userInfoUrl = "https://graph.microsoft.com/v1.0/me";

        return webClient.get()
                .uri(userInfoUrl)
                .header("Authorization", "Bearer " + accessToken)
                .retrieve()
                .bodyToMono(MicrosoftUserInfo.class)
                .block();
    }

    /**
     * Procesa el flujo completo de autenticación con Microsoft.
     * 
     * Este método orquesta todo el proceso de autenticación:
     * 1. Intercambia el código por un token de acceso
     * 2. Obtiene la información del usuario de Microsoft Graph
     * 3. Determina el email (puede estar en "mail" o "userPrincipalName")
     * 4. Busca o crea el usuario en la base de datos local
     * 5. Asigna el rol "CIUDADANO" si es un nuevo usuario
     * 6. Genera y retorna un token JWT propio
     * 
     * NOTA: El campo "mail" puede ser null en cuentas personales de Microsoft,
     * en cuyo caso se utiliza "userPrincipalName" como alternativa.
     * 
     * @param code Código de autorización recibido de Microsoft
     * @return Token JWT para autenticación en la aplicación
     * @throws RuntimeException Si no se puede obtener el email o si ya está registrado
     */
    public String processMicrosoftLogin(String code) {
        String accessToken = exchangeCodeForAccessToken(code);
        MicrosoftUserInfo microsoftUser = getUserInfo(accessToken);
        
        String email = microsoftUser.getMail();
        if (email == null || email.isEmpty()) {
            email = microsoftUser.getUserPrincipalName();
        }
        
        if (email == null || email.isEmpty()) {
            throw new RuntimeException("No se pudo obtener el email de la cuenta de Microsoft");
        }
        
        User existingUser = userRepository.getUserByEmail(email);
        
        if (existingUser != null) {
            if (!"MICROSOFT".equals(existingUser.getAuthProvider())) {
                throw new RuntimeException(
                    "Este email ya está registrado. Por favor, inicie sesión con su método original."
                );
            }
            return jwtService.generateToken(existingUser);
        }
        
        String userName = microsoftUser.getDisplayName();
        if (userName == null || userName.isEmpty()) {
            String firstName = microsoftUser.getGivenName();
            String lastName = microsoftUser.getSurname();
            if (firstName != null && lastName != null) {
                userName = firstName + " " + lastName;
            } else if (firstName != null) {
                userName = firstName;
            } else {
                userName = email.split("@")[0];
            }
        }
        
        User newUser = new User(
                userName,
                email,
                "MICROSOFT",
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
