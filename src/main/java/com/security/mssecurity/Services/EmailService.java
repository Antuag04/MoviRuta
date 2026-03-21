package com.security.mssecurity.Services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;

/**
 * Servicio de envío de correos electrónicos del sistema.
 * 
 * Este servicio gestiona el envío de correos transaccionales para:
 * - Códigos de verificación 2FA (autenticación de dos factores)
 * - Enlaces de recuperación de contraseña
 * 
 * Utiliza Spring Mail con configuración SMTP definida en application.properties.
 * Los correos se envían en formato HTML para una mejor presentación.
 * 
 * Configuración requerida:
 * - spring.mail.host: Servidor SMTP (ej: smtp.gmail.com)
 * - spring.mail.port: Puerto SMTP (ej: 587)
 * - spring.mail.username: Usuario de autenticación
 * - spring.mail.password: Contraseña de aplicación
 * - app.mail.from: Dirección de remitente
 * - app.frontend.url: URL del frontend para enlaces
 * 
 * @see RecaptchaService
 * @see SecurityService
 */
@Service
public class EmailService {

    /**
     * Bean de Spring Mail para envío de correos.
     * Se configura automáticamente con las propiedades spring.mail.*
     */
    @Autowired
    private JavaMailSender mailSender;

    /**
     * Dirección de correo que aparecerá como remitente.
     */
    @Value("${app.mail.from}")
    private String fromEmail;

    /**
     * URL base del frontend para construir enlaces.
     */
    @Value("${app.frontend.url}")
    private String frontendUrl;

    /**
     * Envía un código de verificación 2FA al correo del usuario.
     * 
     * Este método se invoca después de que el usuario proporciona
     * credenciales válidas en el login. El código enviado debe ser
     * ingresado por el usuario para completar la autenticación.
     * 
     * El correo incluye:
     * - El código de 6 dígitos en formato destacado
     * - Tiempo de expiración del código
     * - Advertencia de seguridad
     * 
     * @param toEmail Dirección de correo del destinatario
     * @param code    Código de 6 dígitos a enviar
     * @param userName Nombre del usuario para personalizar el mensaje
     * @throws RuntimeException Si ocurre un error al enviar el correo
     */
    public void send2FACode(String toEmail, String code, String userName) {
        String subject = "Código de verificación - MS Security";
        
        String htmlContent = """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                    .header { background-color: #4CAF50; color: white; padding: 20px; text-align: center; }
                    .content { padding: 20px; background-color: #f9f9f9; }
                    .code { font-size: 32px; font-weight: bold; color: #4CAF50; 
                            text-align: center; padding: 20px; letter-spacing: 5px;
                            background-color: #fff; border: 2px dashed #4CAF50; margin: 20px 0; }
                    .warning { color: #856404; background-color: #fff3cd; 
                              padding: 10px; border-radius: 5px; margin-top: 15px; }
                    .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🔐 Verificación de Identidad</h1>
                    </div>
                    <div class="content">
                        <p>Hola <strong>%s</strong>,</p>
                        <p>Se ha solicitado un código de verificación para acceder a su cuenta.</p>
                        <p>Su código de verificación es:</p>
                        <div class="code">%s</div>
                        <p>Este código expira en <strong>5 minutos</strong>.</p>
                        <div class="warning">
                            ⚠️ <strong>Importante:</strong> Si usted no solicitó este código, 
                            ignore este correo. Nunca comparta este código con nadie.
                        </div>
                    </div>
                    <div class="footer">
                        <p>Este es un correo automático, por favor no responda.</p>
                        <p>© 2024 MS Security - Sistema de Autenticación</p>
                    </div>
                </div>
            </body>
            </html>
            """.formatted(userName, code);

        sendHtmlEmail(toEmail, subject, htmlContent);
    }

    /**
     * Envía un enlace de recuperación de contraseña al usuario.
     * 
     * Este método se invoca cuando el usuario solicita restablecer
     * su contraseña. El enlace contiene un token único que permite
     * al usuario acceder al formulario de cambio de contraseña.
     * 
     * El correo incluye:
     * - Enlace con el token de recuperación
     * - Tiempo de expiración del enlace
     * - Instrucciones de seguridad
     * 
     * @param toEmail  Dirección de correo del destinatario
     * @param token    Token UUID único para la recuperación
     * @param userName Nombre del usuario para personalizar el mensaje
     * @throws RuntimeException Si ocurre un error al enviar el correo
     */
    public void sendPasswordResetLink(String toEmail, String token, String userName) {
        String subject = "Recuperación de contraseña - MS Security";
        String resetUrl = frontendUrl + "/reset-password?token=" + token;
        
        String htmlContent = """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                    .header { background-color: #2196F3; color: white; padding: 20px; text-align: center; }
                    .content { padding: 20px; background-color: #f9f9f9; }
                    .button { display: inline-block; padding: 15px 30px; background-color: #2196F3; 
                             color: white; text-decoration: none; border-radius: 5px; 
                             font-weight: bold; margin: 20px 0; }
                    .button:hover { background-color: #1976D2; }
                    .link-text { word-break: break-all; font-size: 12px; color: #666; 
                                background-color: #eee; padding: 10px; margin: 10px 0; }
                    .warning { color: #856404; background-color: #fff3cd; 
                              padding: 10px; border-radius: 5px; margin-top: 15px; }
                    .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🔑 Recuperación de Contraseña</h1>
                    </div>
                    <div class="content">
                        <p>Hola <strong>%s</strong>,</p>
                        <p>Hemos recibido una solicitud para restablecer la contraseña de su cuenta.</p>
                        <p>Haga clic en el siguiente botón para crear una nueva contraseña:</p>
                        <p style="text-align: center;">
                            <a href="%s" class="button">Restablecer Contraseña</a>
                        </p>
                        <p>O copie y pegue el siguiente enlace en su navegador:</p>
                        <div class="link-text">%s</div>
                        <p>Este enlace expira en <strong>30 minutos</strong>.</p>
                        <div class="warning">
                            ⚠️ <strong>Importante:</strong> Si usted no solicitó este cambio, 
                            ignore este correo. Su contraseña actual permanecerá sin cambios.
                        </div>
                    </div>
                    <div class="footer">
                        <p>Este es un correo automático, por favor no responda.</p>
                        <p>© 2024 MS Security - Sistema de Autenticación</p>
                    </div>
                </div>
            </body>
            </html>
            """.formatted(userName, resetUrl, resetUrl);

        sendHtmlEmail(toEmail, subject, htmlContent);
    }

    /**
     * Método interno para enviar correos en formato HTML.
     * 
     * Utiliza MimeMessage para soportar contenido HTML y caracteres
     * especiales (UTF-8). Maneja la configuración SMTP automáticamente
     * a través del bean JavaMailSender.
     * 
     * @param to      Dirección de correo del destinatario
     * @param subject Asunto del correo
     * @param htmlContent Contenido HTML del correo
     * @throws RuntimeException Si ocurre un error al enviar el correo
     */
    private void sendHtmlEmail(String to, String subject, String htmlContent) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
            
            helper.setFrom(fromEmail);
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(htmlContent, true); // true = es HTML
            
            mailSender.send(message);
            System.out.println("[EMAIL] Correo enviado exitosamente a: " + to);
            
        } catch (MessagingException e) {
            System.err.println("[EMAIL] Error al enviar correo a " + to + ": " + e.getMessage());
            throw new RuntimeException("Error al enviar el correo electrónico. Por favor, intente más tarde.");
        }
    }
}
