package com.security.mssecurity.Services;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.Map;

/**
 * Servicio de validación de tokens reCAPTCHA v3 de Google.
 * 
 * reCAPTCHA v3 es un sistema de protección contra bots que funciona de forma
 * invisible, analizando el comportamiento del usuario y asignando un score
 * de 0.0 (muy probable bot) a 1.0 (muy probable humano).
 * 
 * Flujo de validación:
 * 1. El frontend carga el script de reCAPTCHA y genera un token
 * 2. El frontend envía el token junto con la petición (login, etc.)
 * 3. Este servicio envía el token a la API de Google para validación
 * 4. Google responde con el score y si la validación fue exitosa
 * 5. Si el score supera el umbral configurado (0.5), se permite la acción
 * 
 * Configuración requerida en application.properties:
 * - recaptcha.secret: Clave secreta obtenida de la consola de reCAPTCHA
 * - recaptcha.verify-url: URL de la API de verificación de Google
 * - recaptcha.threshold: Score mínimo aceptado (0.0 - 1.0)
 * 
 * @see <a href="https://developers.google.com/recaptcha/docs/v3">Documentación reCAPTCHA v3</a>
 */
@Service
public class RecaptchaService {

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
     * Valor recomendado: 0.5 (puede ajustarse según necesidades)
     */
    @Value("${recaptcha.threshold}")
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
     * Valida un token reCAPTCHA con la API de Google.
     * 
     * El proceso de validación incluye:
     * 1. Envío del token y la clave secreta a la API de Google
     * 2. Recepción de la respuesta con el resultado de la validación
     * 3. Verificación de que success sea true
     * 4. Verificación de que el score supere el umbral configurado
     * 
     * Ejemplo de respuesta de Google:
     * {
     *   "success": true,
     *   "score": 0.9,
     *   "action": "login",
     *   "challenge_ts": "2024-01-01T00:00:00Z",
     *   "hostname": "localhost"
     * }
     * 
     * @param token Token generado por el widget reCAPTCHA en el frontend
     * @return true si el token es válido y el score supera el umbral, false en caso contrario
     */
    public boolean validateToken(String token) {
        // ⚠️ SOLO PARA DESARROLLO - Remover en producción
        if ("BYPASS_FOR_TESTING".equals(token)) {
            System.out.println("[reCAPTCHA] BYPASS activado - Solo desarrollo");
            return true;
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
                System.out.println("[reCAPTCHA] Respuesta nula de Google - Rechazado");
                return false;
            }

            // Extraer valores de la respuesta
            Boolean success = (Boolean) response.get("success");
            Double score = response.get("score") != null 
                    ? ((Number) response.get("score")).doubleValue() 
                    : 0.0;

            // Log para debugging (útil durante desarrollo)
            System.out.println("[reCAPTCHA] Success: " + success + ", Score: " + score);

            // Validar success y score
            if (Boolean.TRUE.equals(success) && score >= threshold) {
                System.out.println("[reCAPTCHA] Validación exitosa - Score: " + score);
                return true;
            } else {
                System.out.println("[reCAPTCHA] Validación fallida - Success: " + success + ", Score: " + score + ", Threshold: " + threshold);
                return false;
            }

        } catch (Exception e) {
            // En caso de error de red o parsing, registrar y rechazar
            System.err.println("[reCAPTCHA] Error al validar token: " + e.getMessage());
            return false;
        }
    }

    /**
     * Valida un token reCAPTCHA y lanza excepción si falla.
     * 
     * Este método es una variante de validateToken que facilita su uso
     * en flujos donde se prefiere manejar la validación mediante excepciones.
     * 
     * @param token Token generado por el widget reCAPTCHA en el frontend
     * @throws RuntimeException Si el token es inválido o el score es bajo
     */
    public void validateTokenOrThrow(String token) {
        if (!validateToken(token)) {
            throw new RuntimeException("Verificación reCAPTCHA fallida. Por favor, intente nuevamente.");
        }
    }
}
