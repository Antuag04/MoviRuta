package com.security.mssecurity.Services;

import jakarta.mail.internet.MimeMessage;
import org.springframework.beans.factory.annotation.Value;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    private static final Logger logger = LoggerFactory.getLogger(EmailService.class);

    private final JavaMailSender mailSender;

    @Value("${app.mail.from}")
    private String fromEmail;

    @Value("${app.frontend.url}")
    private String frontendUrl;

    public EmailService(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    public void send2FACode(String toEmail, String code, String userName) {
        String subject = "Codigo de verificacion - MoviRuta";
        String htmlContent = buildEmailLayout(
                "Verificacion segura",
                "Tu codigo de acceso temporal",
                userName,
                """
                <p style="margin: 0 0 16px; font-size: 15px; line-height: 1.7; color: #334155;">
                    Usa el siguiente codigo para completar tu verificacion de identidad en MoviRuta.
                </p>
                <div style="margin: 24px 0; padding: 20px; border-radius: 16px; background: #eff6ff; border: 1px solid #bfdbfe; text-align: center;">
                    <div style="margin-bottom: 8px; font-size: 12px; font-weight: 700; letter-spacing: 1.8px; text-transform: uppercase; color: #2563eb;">
                        Codigo de verificacion
                    </div>
                    <div style="font-size: 34px; font-weight: 800; letter-spacing: 8px; color: #0f172a;">
                        %s
                    </div>
                </div>
                <div style="padding: 14px 16px; border-left: 4px solid #2563eb; background: #f8fbff; border-radius: 12px; font-size: 14px; line-height: 1.6; color: #475569;">
                    Este codigo expira en 5 minutos. Si no intentaste iniciar sesion, ignora este mensaje.
                </div>
                """.formatted(escapeHtml(code)),
                null,
                null
        );
        sendEmail(toEmail, subject, htmlContent);
    }

    public void sendPasswordResetLink(String toEmail, String token, String userName) {
        String subject = "Recuperacion de contraseña - MoviRuta";
        String resetUrl = frontendUrl + "/resetpassword?token=" + token;
        String htmlContent = buildEmailLayout(
                "Recuperacion de cuenta",
                "Restablece tu contrasena",
                userName,
                """
                <p style="margin: 0 0 16px; font-size: 15px; line-height: 1.7; color: #334155;">
                    Recibimos una solicitud para cambiar la contraseña de tu cuenta. Para continuar, haz clic en el siguiente boton:
                </p>
                <div style="margin: 28px 0; text-align: center;">
                    <a href="%s" style="display: inline-block; padding: 14px 28px; border-radius: 12px; background: #2563eb; color: #ffffff; text-decoration: none; font-size: 15px; font-weight: 700;">
                        Restablecer contraseña
                    </a>
                </div>
                <div style="padding: 14px 16px; border-radius: 12px; background: #eff6ff; border: 1px solid #bfdbfe; font-size: 14px; line-height: 1.6; color: #475569;">
                    Este enlace expira en 30 minutos. Si no realizaste esta solicitud, puedes ignorar este correo con tranquilidad.
                </div>
                <p style="margin: 18px 0 0; font-size: 13px; line-height: 1.6; color: #64748b;">
                    Si el boton no funciona, copia y pega este enlace en tu navegador:<br>
                    <span style="color: #1d4ed8; word-break: break-all;">%s</span>
                </p>
                """.formatted(resetUrl, escapeHtml(resetUrl)),
                null,
                null
        );
        sendEmail(toEmail, subject, htmlContent);
    }

    public void sendWelcomeEmail(String toEmail, String userName) {
        String subject = "Bienvenido a MoviRuta";
        String htmlContent = buildEmailLayout(
                "Nueva cuenta",
                "Tu registro fue exitoso",
                userName,
                """
                <p style="margin: 0 0 16px; font-size: 15px; line-height: 1.7; color: #334155;">
                    Tu cuenta en MoviRuta fue creada correctamente. Ya puedes iniciar sesion y acceder a las funciones de la plataforma.
                </p>
                <div style="margin: 24px 0; padding: 16px 18px; border-radius: 14px; background: #eff6ff; border: 1px solid #bfdbfe;">
                    <div style="font-size: 14px; font-weight: 700; color: #1e3a8a; margin-bottom: 8px;">Que sigue ahora</div>
                    <div style="font-size: 14px; line-height: 1.7; color: #475569;">
                        Completa tu perfil, verifica tus datos y mantente atento a cualquier notificacion de seguridad.
                    </div>
                </div>
                <div style="text-align: center; margin-top: 28px;">
                    <a href="%s/login" style="display: inline-block; padding: 14px 28px; border-radius: 12px; background: #2563eb; color: #ffffff; text-decoration: none; font-size: 15px; font-weight: 700;">
                        Ir al inicio de sesion
                    </a>
                </div>
                """.formatted(frontendUrl),
                "Gracias por confiar en MoviRuta.",
                null
        );
        sendEmail(toEmail, subject, htmlContent);
    }

    public void sendRoleChangeNotification(String toEmail, String userName, String details) {
        sendNotificationEmail(
                toEmail,
                "Actualizacion de roles - MoviRuta",
                "Tus roles fueron actualizados",
                userName,
                details
        );
    }

    public void sendPermissionChangeNotification(String toEmail, String userName, String details) {
        sendNotificationEmail(
                toEmail,
                "Actualizacion de permisos - MoviRuta",
                "Tus permisos fueron actualizados",
                userName,
                details
        );
    }

    private void sendNotificationEmail(String toEmail, String subject, String title, String userName, String details) {
        String htmlContent = buildEmailLayout(
                "Actualizacion de seguridad",
                title,
                userName,
                """
                <p style="margin: 0 0 16px; font-size: 15px; line-height: 1.7; color: #334155;">
                    Registramos una actualizacion importante en tu cuenta:
                </p>
                <div style="padding: 18px; border-radius: 14px; background: #eff6ff; border: 1px solid #bfdbfe; font-size: 14px; line-height: 1.7; color: #475569;">
                    %s
                </div>
                """.formatted(formatMultilineHtml(details)),
                "Si no reconoces este cambio, revisa tu cuenta lo antes posible.",
                null
        );
        sendEmail(toEmail, subject, htmlContent);
    }

    private String buildEmailLayout(
            String eyebrow,
            String title,
            String userName,
            String bodyContent,
            String footerMessage,
            String secondaryNote
    ) {
        String safeUserName = escapeHtml(userName);
        String safeFooterMessage = footerMessage == null ? "" : """
                <p style="margin: 22px 0 0; font-size: 14px; line-height: 1.6; color: #475569;">
                    %s
                </p>
                """.formatted(escapeHtml(footerMessage));
        String safeSecondaryNote = secondaryNote == null ? "" : """
                <p style="margin: 12px 0 0; font-size: 12px; line-height: 1.6; color: #94a3b8;">
                    %s
                </p>
                """.formatted(escapeHtml(secondaryNote));

        return """
            <html>
            <body style="margin: 0; padding: 32px 16px; background: #eaf2ff; font-family: Arial, sans-serif; color: #0f172a;">
                <div style="max-width: 640px; margin: 0 auto;">
                    <div style="padding: 24px 28px; background: linear-gradient(135deg, #1d4ed8 0%%, #2563eb 100%%); border-radius: 24px 24px 0 0; color: #ffffff;">
                        <div style="font-size: 12px; font-weight: 700; letter-spacing: 2px; text-transform: uppercase; opacity: 0.9;">MoviRuta</div>
                        <div style="margin-top: 10px; font-size: 26px; font-weight: 800; line-height: 1.3;">%s</div>
                        <div style="margin-top: 8px; font-size: 14px; line-height: 1.6; color: #dbeafe;">%s</div>
                    </div>
                    <div style="background: #ffffff; border: 1px solid #dbeafe; border-top: none; border-radius: 0 0 24px 24px; padding: 32px 28px; box-shadow: 0 18px 40px rgba(37, 99, 235, 0.10);">
                        <p style="margin: 0 0 18px; font-size: 15px; line-height: 1.7; color: #334155;">
                            Hola <strong style="color: #0f172a;">%s</strong>,
                        </p>
                        %s
                        %s
                        %s
                        <div style="margin-top: 28px; padding-top: 18px; border-top: 1px solid #e2e8f0; font-size: 12px; line-height: 1.6; color: #94a3b8;">
                            Este correo fue generado automaticamente por MoviRuta.
                        </div>
                    </div>
                </div>
            </body>
            </html>
            """.formatted(
                escapeHtml(title),
                escapeHtml(eyebrow),
                safeUserName,
                bodyContent,
                safeFooterMessage,
                safeSecondaryNote
        );
    }

    private String formatMultilineHtml(String text) {
        return escapeHtml(text).replace("\n", "<br>");
    }

    private String escapeHtml(String value) {
        if (value == null) {
            return "";
        }

        return value
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }

    private void sendEmail(String toEmail, String subject, String htmlContent) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, "UTF-8");
            helper.setFrom(fromEmail);
            helper.setTo(toEmail);
            helper.setSubject(subject);
            helper.setText(htmlContent, true);
            mailSender.send(message);
        } catch (Exception e) {
            logger.warn(
                    "No se pudo enviar correo a {} con asunto '{}'. El flujo principal continuara.",
                    toEmail,
                    subject,
                    e
            );
        }
    }
}
