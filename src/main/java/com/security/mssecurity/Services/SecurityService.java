package com.security.mssecurity.Services;

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
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Servicio principal de autenticación y registro de usuarios.
 * 
 * Este servicio gestiona las operaciones fundamentales de seguridad:
 * - Registro de nuevos usuarios con validación de datos
 * - Inicio de sesión con reCAPTCHA y autenticación de dos factores (2FA)
 * - Verificación de códigos 2FA
 * - Recuperación de contraseña mediante token por email
 * - Asignación automática del rol "CIUDADANO" a nuevos usuarios
 * 
 * Flujo de autenticación completo:
 * 1. Usuario envía credenciales + token reCAPTCHA
 * 2. Se valida reCAPTCHA con Google
 * 3. Se verifican las credenciales
 * 4. Se genera código 2FA y se envía por email
 * 5. Usuario ingresa el código recibido
 * 6. Se genera y retorna el JWT
 * 
 * Para la autenticación OAuth 2.0, se utilizan servicios especializados
 * por proveedor (GoogleOAuthService, GitHubOAuthService, MicrosoftOAuthService).
 * 
 * @see GoogleOAuthService
 * @see GitHubOAuthService
 * @see MicrosoftOAuthService
 * @see RecaptchaService
 * @see EmailService
 */
@Service
public class SecurityService {

    @Autowired
    private UserRepository theUserRepository;

    @Autowired
    private EncryptionService theEncryptionService;

    @Autowired
    private JwtService theJwtService;

    @Autowired
    private RoleRepository theRoleRepository;

    @Autowired
    private UserRoleRepository theUserRoleRepository;

    @Autowired
    private RecaptchaService theRecaptchaService;

    @Autowired
    private EmailService theEmailService;

    @Autowired
    private SessionRepository theSessionRepository;

    @Autowired
    private ProfileRepository theProfileRepository;

    /**
     * Tiempo de expiración del código 2FA en minutos.
     */
    @Value("${app.2fa.expiration-minutes:5}")
    private int twoFactorExpirationMinutes;
    
    /**
     * Tiempo de expiración del token JWT en milisegundos.
     * Se utiliza para calcular la fecha de expiración de las sesiones.
     */
    @Value("${jwt.expiration}")
    private Long jwtExpiration;

    /**
     * Tiempo de expiración del token de recuperación en minutos.
     */
    @Value("${app.password-reset.expiration-minutes:30}")
    private int resetTokenExpirationMinutes;

    /**
     * Generador de números aleatorios seguro para códigos 2FA.
     */
    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * Autentica un usuario mediante email, contraseña y reCAPTCHA.
     * 
     * Este método implementa el flujo de login seguro con verificación
     * en dos pasos:
     * 
     * Paso 1 - Validaciones:
     * 1. Validar token reCAPTCHA con Google
     * 2. Buscar usuario por email
     * 3. Verificar que no sea usuario OAuth
     * 4. Validar contraseña con BCrypt
     * 
     * Paso 2 - Generación 2FA:
     * 5. Generar código aleatorio de 6 dígitos
     * 6. Guardar código con tiempo de expiración
     * 7. Enviar código por email
     * 
     * @param email          Correo electrónico del usuario
     * @param password       Contraseña del usuario
     * @param recaptchaToken Token generado por reCAPTCHA v3 en el frontend
     * @return Map con "requires2FA": true si las credenciales son válidas
     * @throws RuntimeException Si reCAPTCHA falla, credenciales inválidas, o es usuario OAuth
     */
    public Map<String, Object> login(String email, String password, String recaptchaToken) {
        // Paso 1: Validar reCAPTCHA
        theRecaptchaService.validateTokenOrThrow(recaptchaToken);

        // Paso 2: Buscar usuario
        User theActualUser = this.theUserRepository.getUserByEmail(email);
        if (theActualUser == null) {
            throw new RuntimeException("Credenciales inválidas");
        }

        // Paso 3: Verificar que no sea usuario OAuth
        String provider = theActualUser.getAuthProvider();
        if (provider != null && !"LOCAL".equals(provider)) {
            throw new RuntimeException("Este usuario debe iniciar sesión con " + provider);
        }

        // Paso 4: Validar contraseña
        if (!theEncryptionService.verifyPassword(password, theActualUser.getPassword())) {
            throw new RuntimeException("Credenciales inválidas");
        }

        // Paso 5: Generar código 2FA (6 dígitos)
        String twoFactorCode = generateSecure6DigitCode();

        // Paso 6: Guardar código con expiración
        theActualUser.setTwoFactorCode(twoFactorCode);
        theActualUser.setTwoFactorExpiry(LocalDateTime.now().plusMinutes(twoFactorExpirationMinutes));
        theUserRepository.save(theActualUser);

        // Paso 7: Enviar código por email
        theEmailService.send2FACode(
                theActualUser.getEmail(),
                twoFactorCode,
                theActualUser.getName()
        );

        // Retornar indicador de que se requiere 2FA
        Map<String, Object> response = new HashMap<>();
        response.put("requires2FA", true);
        response.put("message", "Código de verificación enviado al correo electrónico");
        return response;
    }

    /**
     * Verifica el código 2FA y completa la autenticación.
     * 
     * Este método es el segundo paso del proceso de login:
     * 1. Buscar usuario por email
     * 2. Validar que el código coincida
     * 3. Validar que el código no haya expirado
     * 4. Limpiar el código usado (un solo uso)
     * 5. Generar y retornar JWT
     * 
     * @param email Correo electrónico del usuario
     * @param code  Código de 6 dígitos recibido por email
     * @return Token JWT para autenticación en peticiones subsecuentes
     * @throws RuntimeException Si el código es inválido o expiró
     */
    public String verify2FA(String email, String code) {
        // Paso 1: Buscar usuario
        User user = theUserRepository.getUserByEmail(email);
        if (user == null) {
            throw new RuntimeException("Usuario no encontrado");
        }

        // Paso 2: Validar que exista código pendiente
        if (user.getTwoFactorCode() == null) {
            throw new RuntimeException("No hay código de verificación pendiente");
        }

        // Paso 3: Validar código
        if (!code.equals(user.getTwoFactorCode())) {
            throw new RuntimeException("Código de verificación incorrecto");
        }

        // Paso 4: Validar expiración
        if (LocalDateTime.now().isAfter(user.getTwoFactorExpiry())) {
            // Limpiar código expirado
            user.setTwoFactorCode(null);
            user.setTwoFactorExpiry(null);
            theUserRepository.save(user);
            throw new RuntimeException("El código de verificación ha expirado");
        }

        // Paso 5: Limpiar código usado (un solo uso)
        user.setTwoFactorCode(null);
        user.setTwoFactorExpiry(null);
        theUserRepository.save(user);

        // Paso 6: Generar JWT
        String jwtToken = theJwtService.generateToken(user);
        
        // Paso 7: Crear sesión automáticamente
        // Al crear una sesión, registramos el JWT en la base de datos
        // lo que nos permite rastrear sesiones activas y gestionar
        // múltiples dispositivos del mismo usuario
        createSession(user, jwtToken);
        
        return jwtToken;
    }

    /**
     * Solicita la recuperación de contraseña para un usuario.
     * 
     * Este método implementa el flujo seguro de recuperación:
     * 1. Validar token reCAPTCHA
     * 2. Buscar usuario por email (sin revelar si existe)
     * 3. Generar token UUID único
     * 4. Guardar token con tiempo de expiración
     * 5. Enviar enlace de recuperación por email
     * 
     * Por seguridad, este método NO indica si el email existe o no
     * en el sistema, para evitar enumeración de usuarios.
     * 
     * @param email          Correo electrónico del usuario
     * @param recaptchaToken Token generado por reCAPTCHA v3 en el frontend
     * @throws RuntimeException Si reCAPTCHA falla
     */
    public void forgotPassword(String email, String recaptchaToken) {
        // Paso 1: Validar reCAPTCHA
        theRecaptchaService.validateTokenOrThrow(recaptchaToken);

        // Paso 2: Buscar usuario (sin revelar si existe)
        User user = theUserRepository.getUserByEmail(email);
        if (user == null) {
            // Por seguridad, no indicamos que el email no existe
            System.out.println("[SECURITY] Intento de recuperación para email inexistente: " + email);
            return;
        }

        // Paso 3: Verificar que no sea usuario OAuth
        String provider = user.getAuthProvider();
        if (provider != null && !"LOCAL".equals(provider)) {
            System.out.println("[SECURITY] Intento de recuperación para usuario OAuth: " + email);
            return;
        }

        // Paso 4: Generar token UUID único
        String resetToken = UUID.randomUUID().toString();

        // Paso 5: Guardar token con expiración
        user.setResetToken(resetToken);
        user.setResetTokenExpiry(LocalDateTime.now().plusMinutes(resetTokenExpirationMinutes));
        theUserRepository.save(user);

        // Paso 6: Enviar enlace por email
        theEmailService.sendPasswordResetLink(
                user.getEmail(),
                resetToken,
                user.getName()
        );

        System.out.println("[SECURITY] Token de recuperación generado para: " + email);
    }

    /**
     * Restablece la contraseña de un usuario utilizando un token de recuperación.
     * 
     * Este método completa el flujo de recuperación:
     * 1. Buscar usuario por token
     * 2. Validar que el token no haya expirado
     * 3. Encriptar y guardar la nueva contraseña
     * 4. Invalidar el token (un solo uso)
     * 
     * @param token       Token UUID recibido en el enlace de recuperación
     * @param newPassword Nueva contraseña del usuario
     * @throws RuntimeException Si el token es inválido o expiró
     */
    public void resetPassword(String token, String newPassword) {
        // Paso 1: Buscar usuario por token
        User user = theUserRepository.findByResetToken(token);
        if (user == null) {
            throw new RuntimeException("Token de recuperación inválido");
        }

        // Paso 2: Validar expiración
        if (LocalDateTime.now().isAfter(user.getResetTokenExpiry())) {
            // Limpiar token expirado
            user.setResetToken(null);
            user.setResetTokenExpiry(null);
            theUserRepository.save(user);
            throw new RuntimeException("El token de recuperación ha expirado");
        }

        // Paso 3: Validar nueva contraseña
        if (newPassword == null || newPassword.trim().length() < 6) {
            throw new RuntimeException("La contraseña debe tener al menos 6 caracteres");
        }

        // Paso 4: Encriptar y guardar nueva contraseña
        user.setPassword(theEncryptionService.encryptPassword(newPassword));

        // Paso 5: Invalidar token (un solo uso)
        user.setResetToken(null);
        user.setResetTokenExpiry(null);
        theUserRepository.save(user);

        System.out.println("[SECURITY] Contraseña restablecida para: " + user.getEmail());
    }

    /**
     * Registra un nuevo usuario en el sistema.
     * 
     * El proceso de registro incluye:
     * 1. Validación de campos obligatorios (nombre, email, contraseña)
     * 2. Verificación de que el email no esté registrado
     * 3. Encriptación de la contraseña con BCrypt
     * 4. Asignación del proveedor "LOCAL"
     * 5. Persistencia del usuario en la base de datos
     * 6. Asignación automática del rol "CIUDADANO"
     * 
     * @param newUser Objeto User con los datos del nuevo usuario
     * @return Usuario creado con su ID asignado
     * @throws RuntimeException Si los datos son inválidos o el email ya existe
     */
    public User register(User newUser) {
        if (newUser.getName() == null || newUser.getName().trim().isEmpty()) {
            throw new RuntimeException("El nombre es obligatorio");
        }
        if (newUser.getEmail() == null || newUser.getEmail().trim().isEmpty()) {
            throw new RuntimeException("El email es obligatorio");
        }
        if (newUser.getPassword() == null || newUser.getPassword().trim().isEmpty()) {
            throw new RuntimeException("La contraseña es obligatoria");
        }

        User existing = theUserRepository.getUserByEmail(newUser.getEmail());
        if (existing != null) {
            throw new RuntimeException("El email ya está registrado");
        }

        newUser.setPassword(theEncryptionService.encryptPassword(newUser.getPassword()));
        newUser.setAuthProvider("LOCAL");

        User savedUser = theUserRepository.save(newUser);

        Role ciudadanoRole = theRoleRepository.findByName("CIUDADANO");
        if (ciudadanoRole != null) {
            UserRole userRole = new UserRole(savedUser, ciudadanoRole);
            theUserRoleRepository.save(userRole);
        } else {
            System.out.println("ADVERTENCIA: El rol 'Ciudadano' no existe en la base de datos");
        }
        
        // Crear perfil predeterminado automáticamente
        // El perfil se crea con valores null para phone y photo,
        // permitiendo que el usuario los complete posteriormente
        // desde su panel de configuración o perfil
        createDefaultProfile(savedUser);

        return savedUser;
    }

    /**
     * Genera un código numérico aleatorio de 6 dígitos para 2FA.
     * 
     * Utiliza SecureRandom para garantizar que el código sea
     * criptográficamente seguro y no predecible.
     * 
     * @return String con el código de 6 dígitos (ej: "847291")
     */
    private String generateSecure6DigitCode() {
        int code = 100000 + secureRandom.nextInt(900000);
        return String.valueOf(code);
    }
    
    /**
     * Crea y persiste una nueva sesión para un usuario.
     * 
     * Este método encapsula la lógica de creación de sesiones, que se ejecuta
     * cada vez que un usuario inicia sesión exitosamente (ya sea mediante
     * login local con 2FA o mediante OAuth con Google/GitHub/Microsoft).
     * 
     * La sesión vincula el token JWT generado con el usuario, permitiendo:
     * - Rastrear todas las sesiones activas de un usuario
     * - Implementar "cerrar sesión desde todos los dispositivos"
     * - Invalidar tokens específicos sin afectar otros
     * - Auditar accesos y actividad del usuario
     * - Detectar accesos simultáneos sospechosos
     * 
     * IMPORTANTE: La fecha de expiración de la sesión debe coincidir con
     * la expiración del JWT. Por defecto, los JWT expiran en 1 hora
     * (configurable en application.properties con jwt.expiration).
     * 
     * Relación: User (1) → Session (N)
     * Un usuario puede tener múltiples sesiones activas (una por dispositivo),
     * pero cada sesión pertenece a un solo usuario.
     * 
     * Ejemplo de uso interno:
     * ```java
     * String jwtToken = theJwtService.generateToken(user);
     * createSession(user, jwtToken); // Registra la sesión en BD
     * return jwtToken; // Retorna al cliente
     * ```
     * 
     * @param user Usuario propietario de la sesión
     * @param token Token JWT generado para esta sesión
     * @return Session creada y persistida en la base de datos
     */
    private Session createSession(User user, String token) {
        // Crear sesión con token, fecha de expiración y sin código 2FA
        Session session = new Session(
            token,
            new Date(System.currentTimeMillis() + jwtExpiration),
            null
        );
        
        // Vincular sesión con usuario mediante referencia @DBRef
        session.setUser(user);
        
        // Persistir en MongoDB
        return theSessionRepository.save(session);
    }
    
    /**
     * Crea y persiste un perfil predeterminado para un usuario.
     * 
     * Este método se ejecuta automáticamente al registrar un nuevo usuario
     * (tanto para registro local como para primer login OAuth). Crear el
     * perfil desde el inicio tiene varios beneficios:
     * 
     * 1. Separación de responsabilidades:
     *    - User: datos de autenticación (email, password, authProvider)
     *    - Profile: datos de perfil/presentación (phone, photo)
     * 
     * 2. Escalabilidad:
     *    - Permite agregar más campos a Profile sin modificar User
     *    - Queries más eficientes (solo cargar User o Profile según necesidad)
     * 
     * 3. Experiencia de usuario:
     *    - El usuario siempre tiene un perfil disponible
     *    - Frontend puede asumir que el perfil existe
     *    - No necesita validar null en cada operación
     * 
     * El perfil se crea con valores null para phone y photo, que el usuario
     * puede completar posteriormente desde su configuración.
     * 
     * Relación: User (1) ↔ Profile (1)
     * Relación bidireccional uno-a-uno. Un usuario tiene un perfil,
     * y un perfil pertenece a un solo usuario.
     * 
     * Ejemplo de uso interno:
     * ```java
     * User savedUser = theUserRepository.save(newUser);
     * createDefaultProfile(savedUser); // Crea perfil vacío
     * ```
     * 
     * @param user Usuario propietario del perfil
     * @return Profile creado y persistido en la base de datos
     */
    private Profile createDefaultProfile(User user) {
        // Crear perfil con valores null (usuario los completará después)
        Profile profile = new Profile(null, null);
        
        // Vincular perfil con usuario mediante referencia @DBRef
        profile.setUser(user);
        
        // Persistir en MongoDB
        return theProfileRepository.save(profile);
    }
    
    /**
     * Crea y persiste un perfil con foto para un usuario OAuth.
     * 
     * Este método se utiliza cuando el proveedor OAuth (Google, GitHub, Microsoft)
     * proporciona una URL de foto de perfil del usuario. Aprovechar esta
     * información mejora la experiencia del usuario al:
     * 
     * 1. Tener una foto de perfil desde el primer momento
     * 2. Evitar que el usuario tenga que subir/configurar una foto manualmente
     * 3. Mantener consistencia con su identidad en el proveedor OAuth
     * 
     * Proveedores OAuth y sus fotos:
     * - Google: Proporciona 'picture' en GoogleUserInfo (alta resolución)
     * - GitHub: Proporciona 'avatar_url' en GitHubUserInfo (tamaño configurable)
     * - Microsoft: Puede proporcionar foto mediante Graph API (opcional)
     * 
     * NOTA IMPORTANTE: La URL de la foto es externa (alojada en Google/GitHub/etc).
     * Si necesitas alojar las fotos localmente, deberías:
     * 1. Descargar la imagen del proveedor OAuth
     * 2. Subirla a tu servidor/cloud storage
     * 3. Guardar la URL local en el perfil
     * 
     * El teléfono (phone) se deja null ya que los proveedores OAuth
     * generalmente no comparten esta información por privacidad.
     * 
     * Ejemplo de uso interno:
     * ```java
     * GoogleUserInfo googleUser = getUserInfo(accessToken);
     * User savedUser = userRepository.save(newUser);
     * createProfileWithPhoto(savedUser, googleUser.getPicture());
     * ```
     * 
     * @param user Usuario propietario del perfil
     * @param photoUrl URL de la foto de perfil proporcionada por el proveedor OAuth
     * @return Profile creado y persistido en la base de datos
     */
    private Profile createProfileWithPhoto(User user, String photoUrl) {
        // Crear perfil con foto del proveedor OAuth, phone null
        Profile profile = new Profile(null, photoUrl);
        
        // Vincular perfil con usuario mediante referencia @DBRef
        profile.setUser(user);
        
        // Persistir en MongoDB
        return theProfileRepository.save(profile);
    }
}
