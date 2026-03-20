package com.security.mssecurity.Configurations;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Configuración de Spring Security para el microservicio.
 * 
 * Esta clase configura el comportamiento de Spring Security, desactivando
 * los mecanismos de seguridad por defecto para permitir que la aplicación
 * implemente su propio sistema de autorización mediante interceptores personalizados.
 * 
 * IMPORTANTE: La seguridad real de la aplicación es gestionada por
 * {@link com.security.mssecurity.Interceptors.SecurityInterceptor}, el cual
 * valida los tokens JWT y verifica los permisos de los usuarios.
 * 
 * @see com.security.mssecurity.Interceptors.SecurityInterceptor
 * @see WebConfig
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /**
     * Configura la cadena de filtros de seguridad de Spring Security.
     * 
     * Se desactivan las siguientes funcionalidades por defecto:
     * - CSRF: No es necesario para APIs REST stateless
     * - Formulario de login: Se utiliza autenticación basada en tokens JWT
     * - OAuth2 automático: El flujo OAuth2 se gestiona manualmente en los controladores
     * 
     * Todas las peticiones HTTP son permitidas a nivel de Spring Security,
     * delegando la autorización al interceptor personalizado de la aplicación.
     * 
     * @param http Objeto HttpSecurity para configurar la seguridad
     * @return SecurityFilterChain configurado
     * @throws Exception Si ocurre un error durante la configuración
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            
            .authorizeHttpRequests(auth -> auth
                .anyRequest().permitAll()
            )
            
            .formLogin(form -> form.disable())
            
            .oauth2Login(oauth -> oauth.disable());
        
        return http.build();
    }
}
