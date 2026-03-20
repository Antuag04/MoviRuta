package com.security.mssecurity.Configurations;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Configuración de Spring Security.
 * 
 * Le decimos a Spring Security que PERMITA todas las peticiones
 * porque nosotros manejamos la seguridad con nuestro propio interceptor (SecurityInterceptor).
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // Desactivar CSRF (no necesario para APIs REST)
            .csrf(csrf -> csrf.disable())
            
            // Permitir TODAS las peticiones (nuestro interceptor se encarga de la seguridad)
            .authorizeHttpRequests(auth -> auth
                .anyRequest().permitAll()
            )
            
            // Desactivar el formulario de login por defecto de Spring Security
            .formLogin(form -> form.disable())
            
            // Desactivar el flujo OAuth2 automático de Spring (lo manejamos manualmente)
            .oauth2Login(oauth -> oauth.disable());
        
        return http.build();
    }
}
