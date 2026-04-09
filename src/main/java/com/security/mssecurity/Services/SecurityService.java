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
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class SecurityService {

    private static final int TWO_FACTOR_MAX_ATTEMPTS = 3;
    private static final String PASSWORD_POLICY_MESSAGE =
            "La contraseña debe tener mínimo 8 caracteres, incluir mayúscula, minúscula, número y carácter especial";

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

    @Value("${app.2fa.expiration-minutes:5}")
    private int twoFactorExpirationMinutes;

    @Value("${jwt.expiration}")
    private Long jwtExpiration;

    @Value("${app.password-reset.expiration-minutes:30}")
    private int resetTokenExpirationMinutes;

    private final SecureRandom secureRandom = new SecureRandom();

    public Map<String, Object> login(String email, String password, String recaptchaToken) {
        theRecaptchaService.validateTokenOrThrow(recaptchaToken);

        User theActualUser = this.theUserRepository.getUserByEmail(email);
        if (theActualUser == null) {
            throw new RuntimeException("Credenciales inválidas");
        }

        String provider = theActualUser.getAuthProvider();
        if (provider != null && !"LOCAL".equals(provider)) {
            throw new RuntimeException("Este usuario debe iniciar sesión con " + provider);
        }

        if (!theEncryptionService.verifyPassword(password, theActualUser.getPassword())) {
            throw new RuntimeException("Credenciales inválidas");
        }

        initiateTwoFactorChallenge(theActualUser);

        Map<String, Object> response = new HashMap<>();
        response.put("requires2FA", true);
        response.put("email", email);
        response.put("message", "Código de verificación enviado al correo electrónico");
        return response;
    }

    public Map<String, Object> resend2FACode(String email, String recaptchaToken) {
        theRecaptchaService.validateTokenOrThrow(recaptchaToken);

        User user = theUserRepository.getUserByEmail(email);
        if (user == null || !"LOCAL".equals(user.getAuthProvider())) {
            throw new RuntimeException("Debe iniciar sesión nuevamente");
        }

        if (user.getTwoFactorCode() == null) {
            throw new RuntimeException("No existe una verificación pendiente");
        }

        initiateTwoFactorChallenge(user);

        Map<String, Object> response = new HashMap<>();
        response.put("requires2FA", true);
        response.put("email", email);
        response.put("message", "Código reenviado correctamente");
        return response;
    }

    public String verify2FA(String email, String code) {
        User user = theUserRepository.getUserByEmail(email);
        if (user == null) {
            throw new RuntimeException("Usuario no encontrado");
        }

        if (user.getTwoFactorCode() == null || user.getTwoFactorExpiry() == null) {
            throw new RuntimeException("No hay un proceso 2FA pendiente");
        }

        if (LocalDateTime.now().isAfter(user.getTwoFactorExpiry())) {
            clearTwoFactorChallenge(user);
            throw new RuntimeException("La verificación expiró. Debe iniciar sesión nuevamente");
        }

        if (!code.equals(user.getTwoFactorCode())) {
            int attempts = user.getTwoFactorAttempts() == null ? 1 : user.getTwoFactorAttempts() + 1;
            user.setTwoFactorAttempts(attempts);

            if (attempts >= TWO_FACTOR_MAX_ATTEMPTS) {
                clearTwoFactorChallenge(user);
                throw new RuntimeException("Se alcanzó el máximo de intentos. La sesión pendiente fue invalidada");
            }

            theUserRepository.save(user);
            throw new RuntimeException("Código de verificación incorrecto. Intentos restantes: " + (TWO_FACTOR_MAX_ATTEMPTS - attempts));
        }

        clearTwoFactorChallenge(user);

        String jwtToken = theJwtService.generateToken(user);
        createSession(user, jwtToken);
        return jwtToken;
    }

    public void forgotPassword(String email, String recaptchaToken) {
        theRecaptchaService.validateTokenOrThrow(recaptchaToken);

        User user = theUserRepository.getUserByEmail(email);
        if (user == null) {
            return;
        }

        String provider = user.getAuthProvider();
        if (provider != null && !"LOCAL".equals(provider)) {
            return;
        }

        String resetToken = UUID.randomUUID().toString();
        user.setResetToken(resetToken);
        user.setResetTokenExpiry(LocalDateTime.now().plusMinutes(resetTokenExpirationMinutes));
        theUserRepository.save(user);

        theEmailService.sendPasswordResetLink(user.getEmail(), resetToken, user.getName());
    }

    public void resetPassword(String token, String newPassword) {
        User user = theUserRepository.findByResetToken(token);
        if (user == null) {
            throw new RuntimeException("Token de recuperación inválido");
        }

        if (user.getResetTokenExpiry() == null || LocalDateTime.now().isAfter(user.getResetTokenExpiry())) {
            user.setResetToken(null);
            user.setResetTokenExpiry(null);
            theUserRepository.save(user);
            throw new RuntimeException("El token de recuperación ha expirado");
        }

        validatePasswordPolicy(newPassword);

        user.setPassword(theEncryptionService.encryptPassword(newPassword));
        user.setResetToken(null);
        user.setResetTokenExpiry(null);
        theUserRepository.save(user);
        theSessionRepository.deleteByUser(user);
    }

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

        validatePasswordPolicy(newUser.getPassword());

        newUser.setPassword(theEncryptionService.encryptPassword(newUser.getPassword()));
        newUser.setAuthProvider("LOCAL");

        User savedUser = theUserRepository.save(newUser);

        Role ciudadanoRole = theRoleRepository.findByName("CIUDADANO");
        if (ciudadanoRole != null) {
            UserRole userRole = new UserRole(savedUser, ciudadanoRole);
            theUserRoleRepository.save(userRole);
        }

        createDefaultProfile(savedUser);
        theEmailService.sendWelcomeEmail(savedUser.getEmail(), savedUser.getName());

        return savedUser;
    }

    public void changePassword(User user, String currentPassword, String newPassword) {
        if (currentPassword == null || currentPassword.trim().isEmpty()) {
            throw new RuntimeException("Debe proporcionar su contraseña actual");
        }

        if (newPassword == null || newPassword.trim().isEmpty()) {
            throw new RuntimeException("La nueva contraseña es obligatoria");
        }

        if (!"LOCAL".equals(user.getAuthProvider())) {
            throw new RuntimeException("No puedes cambiar la contraseña para cuentas " + user.getAuthProvider());
        }

        if (!theEncryptionService.verifyPassword(currentPassword, user.getPassword())) {
            throw new RuntimeException("La contraseña actual es incorrecta");
        }

        if (theEncryptionService.verifyPassword(newPassword, user.getPassword())) {
            throw new RuntimeException("La nueva contraseña debe ser diferente a la actual");
        }

        validatePasswordPolicy(newPassword);

        user.setPassword(theEncryptionService.encryptPassword(newPassword));
        theUserRepository.save(user);
        theSessionRepository.deleteByUser(user);
    }

    private void initiateTwoFactorChallenge(User user) {
        String twoFactorCode = generateSecure6DigitCode();
        user.setTwoFactorCode(twoFactorCode);
        user.setTwoFactorExpiry(LocalDateTime.now().plusMinutes(twoFactorExpirationMinutes));
        user.setTwoFactorAttempts(0);
        theUserRepository.save(user);

        theEmailService.send2FACode(user.getEmail(), twoFactorCode, user.getName());
    }

    private void clearTwoFactorChallenge(User user) {
        user.setTwoFactorCode(null);
        user.setTwoFactorExpiry(null);
        user.setTwoFactorAttempts(0);
        theUserRepository.save(user);
    }

    private void validatePasswordPolicy(String password) {
        if (password == null || !password.matches("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[^A-Za-z\\d]).{8,}$")) {
            throw new RuntimeException(PASSWORD_POLICY_MESSAGE);
        }
    }

    private String generateSecure6DigitCode() {
        int code = 100000 + secureRandom.nextInt(900000);
        return String.valueOf(code);
    }

    private Session createSession(User user, String token) {
        Session session = new Session(
                token,
                new Date(System.currentTimeMillis() + jwtExpiration),
                null
        );
        session.setUser(user);
        return theSessionRepository.save(session);
    }

    private Profile createDefaultProfile(User user) {
        Profile profile = new Profile(null, null);
        profile.setUser(user);
        return theProfileRepository.save(profile);
    }
}
