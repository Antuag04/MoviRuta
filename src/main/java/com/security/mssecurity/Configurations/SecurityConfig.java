package com.security.mssecurity.Configurations;

import java.util.Arrays;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * Configuración de Spring Security para el microservicio.
 *
 * Esta clase configura el comportamiento de Spring Security, desactivando
 * los mecanismos de seguridad por defecto para permitir que la aplicación
 * implemente su propio sistema de autorización mediante interceptores personalizados.
 *
 * También configura CORS para permitir que el frontend (localhost:4200)
 * pueda hacer requests al backend.
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
     * Se habilita CORS para permitir requests desde el frontend en localhost:4200.
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
                // Habilitar CORS
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                // Deshabilitar CSRF (no necesario para APIs REST)
                .csrf(csrf -> csrf.disable())

                // Permitir todos los requests (seguridad delegada al SecurityInterceptor)
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().permitAll()
                )

                // Deshabilitar formulario de login por defecto
                .formLogin(form -> form.disable())

                // Deshabilitar OAuth2 automático
                .oauth2Login(oauth -> oauth.disable());

        return http.build();
    }

    /**
     * Configura la fuente de configuración de CORS.
     *
     * Define qué orígenes, métodos y headers son permitidos
     * para hacer requests al backend desde el frontend.
     *
     * @return CorsConfigurationSource configurada
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // Orígenes permitidos (solo localhost:4200)
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:4200"));

        // Métodos HTTP permitidos
        configuration.setAllowedMethods(Arrays.asList(
                "GET",      // Obtener datos
                "POST",     // Crear datos
                "PUT",      // Actualizar datos
                "DELETE",   // Borrar datos
                "OPTIONS"   // Preflight del navegador
        ));

        // Headers permitidos (todos)
        configuration.setAllowedHeaders(Arrays.asList("*"));

        // Headers expuestos (opcionales, pero recomendado)
        configuration.setExposedHeaders(Arrays.asList(
                "Authorization",
                "Content-Type"
        ));

        // Permitir credenciales (tokens, cookies)
        configuration.setAllowCredentials(true);

        // Tiempo de caché (en segundos)
        configuration.setMaxAge(3600L);  // 1 hora

        // Aplicar configuración a todos los paths
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }
}