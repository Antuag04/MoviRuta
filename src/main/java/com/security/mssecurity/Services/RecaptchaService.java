package com.security.mssecurity.Services;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.Map;

/**
 * Servicio de validación de tokens reCAPTCHA v3 (Invisible) de Google.
 * 
 * reCAPTCHA v3 es un sistema de protección contra bots que funciona de forma
 * completamente invisible para el usuario. En lugar de requerir interacción,
 * analiza el comportamiento del usuario y asigna un score de 0.0 a 1.0.
 * 
 * Scores:
 * - 1.0: Muy probablemente un humano legítimo
 * - 0.0: Muy probablemente un bot
 * - Threshold recomendado: 0.5 (configurable según necesidades)
 * 
 * Flujo de validación:
 * 1. El frontend carga el script de reCAPTCHA v3 con la site key
 * 2. Al enviar un formulario, el frontend ejecuta grecaptcha.execute(siteKey, {action: 'login'})
 * 3. Google analiza el comportamiento y genera un token con el score
 * 4. El frontend envía el token junto con la petición (login, etc.)
 * 5. Este servicio envía el token a la API de Google para validación
 * 6. Google responde con success, score y action
 * 7. El backend verifica que score >= threshold y action coincida
 * 
 * Configuración requerida en application.properties:
 * - recaptcha.site-key: Clave pública para el frontend
 * - recaptcha.secret: Clave secreta para validación en backend
 * - recaptcha.verify-url: URL de la API de verificación de Google
 * - recaptcha.threshold: Score mínimo aceptable (ej: 0.5)
 * 
 * Ejemplo de integración en frontend (Angular):
 * ```typescript
 * // En index.html
 * <script src="https://www.google.com/recaptcha/api.js?render=SITE_KEY"></script>
 * 
 * // En el componente
 * declare var grecaptcha: any;
 * 
 * async login() {
 *   const token = await grecaptcha.execute('SITE_KEY', {action: 'login'});
 *   this.authService.login(email, password, token).subscribe(...);
 * }
 * ```
 * 
 * @see <a href="https://developers.google.com/recaptcha/docs/v3">Documentación reCAPTCHA v3</a>
 */
@Service
public class RecaptchaService {

    /**
     * Clave del sitio (pública) de reCAPTCHA.
     * Se usa en el frontend para cargar el script.
     * Se obtiene de: https://www.google.com/recaptcha/admin
     */
    @Value("${recaptcha.site-key}")
    private String recaptchaSiteKey;

    /**
     * Clave secreta de reCAPTCHA (nunca se expone al frontend).
     * Se obtiene de: https://www.google.com/recaptcha/admin
     */
    @Value("${recaptcha.secret}")
    private String recaptchaSecret;

    /**
     * URL de la API de verificación de Google.
     * Valor estándar: https://www.google.com/recaptcha/api/siteverify
     */
    @Value("${recaptcha.verify-url}")
    private String verifyUrl;

    /**
     * Umbral mínimo de score para considerar la validación exitosa.
     * Valor recomendado: 0.5
     * - Valores más altos (0.7-0.9): Más estricto, puede bloquear usuarios legítimos
     * - Valores más bajos (0.3-0.5): Más permisivo, puede permitir algunos bots
     */
    @Value("${recaptcha.threshold:0.5}")
    private double threshold;

    /**
     * Cliente HTTP reactivo para realizar peticiones a la API de Google.
     */
    private final WebClient webClient;

    /**
     * Constructor que inicializa el cliente WebClient.
     */
    public RecaptchaService() {
        this.webClient = WebClient.builder().build();
    }

    /**
     * Valida un token reCAPTCHA v3 con la API de Google.
     * 
     * El proceso de validación incluye:
     * 1. Envío del token y la clave secreta a la API de Google
     * 2. Recepción de la respuesta con success, score y action
     * 3. Verificación de que success sea true
     * 4. Verificación de que score >= threshold configurado
     * 
     * Ejemplo de respuesta exitosa de Google:
     * {
     *   "success": true,
     *   "score": 0.9,
     *   "action": "login",
     *   "challenge_ts": "2024-01-01T00:00:00Z",
     *   "hostname": "localhost"
     * }
     * 
     * Ejemplo de respuesta fallida de Google:
     * {
     *   "success": false,
     *   "error-codes": ["invalid-input-response"]
     * }
     * 
     * @param token Token generado por grecaptcha.execute() en el frontend
     * @return true si el token es válido y el score >= threshold, false en caso contrario
     */
    public boolean validateToken(String token) {
        // Validación inicial: si no hay token, rechazar inmediatamente
        if (token == null || token.trim().isEmpty()) {
            System.out.println("[reCAPTCHA v3] Token vacío o nulo - Rechazado");
            return false;
        }

        try {
            // Realizar petición POST a la API de Google
            Map<String, Object> response = webClient.post()
                    .uri(verifyUrl)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(BodyInserters
                            .fromFormData("secret", recaptchaSecret)
                            .with("response", token))
                    .retrieve()
                    .bodyToMono(Map.class)
                    .block();

            // Validar que la respuesta no sea nula
            if (response == null) {
                System.out.println("[reCAPTCHA v3] Respuesta nula de Google - Rechazado");
                return false;
            }

            // Extraer valores de la respuesta
            Boolean success = (Boolean) response.get("success");
            Double score = response.get("score") != null ? ((Number) response.get("score")).doubleValue() : 0.0;
            String action = (String) response.get("action");

            // Log para debugging (útil durante desarrollo)
            System.out.println("[reCAPTCHA v3] Success: " + success + ", Score: " + score + ", Action: " + action + ", Threshold: " + threshold);

            // Validar success
            if (!Boolean.TRUE.equals(success)) {
                System.out.println("[reCAPTCHA v3] Validación fallida - success=false");
                return false;
            }

            // Validar score contra threshold
            if (score < threshold) {
                System.out.println("[reCAPTCHA v3] Score bajo (" + score + " < " + threshold + ") - Posible bot detectado");
                return false;
            }

            System.out.println("[reCAPTCHA v3] Validación exitosa - Score: " + score);
            return true;

        } catch (Exception e) {
            // En caso de error de red o parsing, registrar y rechazar
            System.err.println("[reCAPTCHA v3] Error al validar token: " + e.getMessage());
            return false;
        }
    }

    /**
     * Valida un token reCAPTCHA v3 verificando también la acción esperada.
     * 
     * Este método añade una capa adicional de seguridad verificando que
     * la acción del token coincida con la esperada. Esto previene que
     * un atacante reutilice un token válido de una acción en otra.
     * 
     * Acciones comunes:
     * - "login": Inicio de sesión
     * - "register": Registro de usuario
     * - "forgot_password": Recuperación de contraseña
     * - "contact": Formulario de contacto
     * 
     * @param token Token generado por grecaptcha.execute() en el frontend
     * @param expectedAction Acción esperada (debe coincidir con la usada en el frontend)
     * @return true si el token es válido, el score >= threshold y la acción coincide
     */
    public boolean validateToken(String token, String expectedAction) {
        // Validación inicial
        if (token == null || token.trim().isEmpty()) {
            System.out.println("[reCAPTCHA v3] Token vacío o nulo - Rechazado");
            return false;
        }

        try {
            // Realizar petición POST a la API de Google
            Map<String, Object> response = webClient.post()
                    .uri(verifyUrl)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(BodyInserters
                            .fromFormData("secret", recaptchaSecret)
                            .with("response", token))
                    .retrieve()
                    .bodyToMono(Map.class)
                    .block();

            if (response == null) {
                System.out.println("[reCAPTCHA v3] Respuesta nula de Google - Rechazado");
                return false;
            }

            Boolean success = (Boolean) response.get("success");
            Double score = response.get("score") != null ? ((Number) response.get("score")).doubleValue() : 0.0;
            String action = (String) response.get("action");

            System.out.println("[reCAPTCHA v3] Success: " + success + ", Score: " + score + ", Action: " + action + ", Expected: " + expectedAction);

            // Validar success
            if (!Boolean.TRUE.equals(success)) {
                System.out.println("[reCAPTCHA v3] Validación fallida - success=false");
                return false;
            }

            // Validar action si se proporciona expectedAction
            if (expectedAction != null && !expectedAction.equals(action)) {
                System.out.println("[reCAPTCHA v3] Acción no coincide (" + action + " != " + expectedAction + ") - Posible ataque");
                return false;
            }

            // Validar score
            if (score < threshold) {
                System.out.println("[reCAPTCHA v3] Score bajo (" + score + " < " + threshold + ") - Posible bot");
                return false;
            }

            System.out.println("[reCAPTCHA v3] Validación exitosa - Score: " + score + ", Action: " + action);
            return true;

        } catch (Exception e) {
            System.err.println("[reCAPTCHA v3] Error al validar token: " + e.getMessage());
            return false;
        }
    }

    /**
     * Valida un token reCAPTCHA v3 y lanza excepción si falla.
     * 
     * Este método es una variante de validateToken que facilita su uso
     * en flujos donde se prefiere manejar la validación mediante excepciones.
     * 
     * @param token Token generado por grecaptcha.execute() en el frontend
     * @throws RuntimeException Si el token es inválido o el score es bajo
     */
    public void validateTokenOrThrow(String token) {
        if (!validateToken(token)) {
            throw new RuntimeException("Verificación reCAPTCHA fallida. Por favor, intente nuevamente.");
        }
    }

    /**
     * Valida un token reCAPTCHA v3 con acción y lanza excepción si falla.
     * 
     * @param token Token generado por grecaptcha.execute() en el frontend
     * @param expectedAction Acción esperada
     * @throws RuntimeException Si el token es inválido, el score es bajo o la acción no coincide
     */
    public void validateTokenOrThrow(String token, String expectedAction) {
        if (!validateToken(token, expectedAction)) {
            throw new RuntimeException("Verificación reCAPTCHA fallida. Por favor, intente nuevamente.");
        }
    }

    /**
     * Obtiene la clave del sitio (site key) para uso en el frontend.
     * 
     * Este método permite exponer la site key a través de un endpoint
     * si se desea cargarla dinámicamente en el frontend.
     * 
     * @return La clave pública del sitio reCAPTCHA
     */
    public String getSiteKey() {
        return recaptchaSiteKey;
    }
}
