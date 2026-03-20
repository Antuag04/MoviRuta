package com.security.mssecurity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Clase principal del microservicio de seguridad (ms-security).
 * 
 * Este microservicio proporciona funcionalidades de autenticación y autorización,
 * incluyendo:
 * - Registro e inicio de sesión tradicional (email/contraseña)
 * - Autenticación mediante OAuth 2.0 (Google, GitHub, Microsoft)
 * - Gestión de usuarios, roles y permisos
 * - Generación y validación de tokens JWT
 * - Control de acceso basado en roles (RBAC)
 * 
 * La aplicación utiliza MongoDB como base de datos y Spring Security
 * para la gestión de seguridad.
 * 
 * @author Equipo de Desarrollo
 * @version 1.0
 */
@SpringBootApplication
public class MsSecurityApplication {

    /**
     * Punto de entrada de la aplicación.
     * Inicializa el contexto de Spring Boot y arranca el servidor embebido.
     * 
     * @param args Argumentos de línea de comandos (opcional)
     */
    public static void main(String[] args) {
        SpringApplication.run(MsSecurityApplication.class, args);
    }

}
