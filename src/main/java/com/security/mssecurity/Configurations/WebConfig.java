package com.security.mssecurity.Configurations;

import com.security.mssecurity.Interceptors.SecurityInterceptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Configuración de Spring MVC para el manejo de interceptores HTTP.
 * 
 * Esta clase registra el interceptor de seguridad que valida las peticiones
 * entrantes, verificando la autenticación y autorización de los usuarios
 * antes de que lleguen a los controladores.
 * 
 * Estructura de rutas:
 * - /api/public/** : Rutas públicas (sin autenticación requerida)
 * - /api/**        : Rutas protegidas (requieren token JWT válido y permisos)
 * 
 * @see SecurityInterceptor
 */
@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Autowired
    private SecurityInterceptor securityInterceptor;

    /**
     * Registra los interceptores de la aplicación.
     * 
     * El interceptor de seguridad se aplica a todas las rutas bajo /api/**,
     * excepto aquellas bajo /api/public/** que son de acceso libre.
     * 
     * Ejemplos de rutas públicas:
     * - /api/public/security/login
     * - /api/public/security/register
     * - /api/public/oauth2/callback/*
     * 
     * @param registry Registro de interceptores de Spring MVC
     */
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(securityInterceptor)
                .addPathPatterns("/api/**")
                .excludePathPatterns("/api/public/**");
    }
}