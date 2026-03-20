package com.security.mssecurity.Interceptors;

import com.security.mssecurity.Services.ValidatorsService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

/**
 * Interceptor de seguridad que valida la autenticación y autorización
 * de las peticiones HTTP antes de que lleguen a los controladores.
 * 
 * Este componente implementa el patrón de control de acceso basado en roles (RBAC),
 * verificando que:
 * 1. El usuario tenga un token JWT válido en el header Authorization
 * 2. El usuario tenga asignado un rol con los permisos necesarios para acceder al recurso
 * 
 * Si la validación falla, se retorna un código HTTP 401 (Unauthorized).
 * 
 * @see com.security.mssecurity.Services.ValidatorsService
 * @see com.security.mssecurity.Configurations.WebConfig
 */
@Component
public class SecurityInterceptor implements HandlerInterceptor {

    @Autowired
    private ValidatorsService validatorService;

    /**
     * Método ejecutado antes de que la petición llegue al controlador.
     * 
     * Realiza la validación de seguridad verificando:
     * - La presencia y validez del token JWT
     * - Los permisos del usuario para acceder a la URL y método HTTP solicitados
     * 
     * @param request  Objeto HttpServletRequest con los datos de la petición
     * @param response Objeto HttpServletResponse para enviar la respuesta
     * @param handler  Manejador que procesará la petición
     * @return true si la petición está autorizada, false en caso contrario
     */
    @Override
    public boolean preHandle(HttpServletRequest request,
                             HttpServletResponse response,
                             Object handler) {
        boolean success = this.validatorService.validationRolePermission(
                request, 
                request.getRequestURI(), 
                request.getMethod()
        );
        
        if (!success) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return false;
        }
        return true;
    }

    /**
     * Método ejecutado después de que el controlador procesa la petición,
     * pero antes de renderizar la vista.
     * 
     * En el contexto de una API REST, este método generalmente no requiere
     * implementación adicional.
     * 
     * @param request      Objeto HttpServletRequest con los datos de la petición
     * @param response     Objeto HttpServletResponse con la respuesta
     * @param handler      Manejador que procesó la petición
     * @param modelAndView Modelo y vista (null en APIs REST)
     * @throws Exception Si ocurre un error durante el procesamiento
     */
    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler,
                           ModelAndView modelAndView) throws Exception {
    }

    /**
     * Método ejecutado después de completar toda la petición,
     * incluyendo la renderización de la vista si aplica.
     * 
     * Útil para tareas de limpieza o logging post-procesamiento.
     * 
     * @param request  Objeto HttpServletRequest con los datos de la petición
     * @param response Objeto HttpServletResponse con la respuesta
     * @param handler  Manejador que procesó la petición
     * @param ex       Excepción lanzada durante el procesamiento (puede ser null)
     * @throws Exception Si ocurre un error durante el procesamiento
     */
    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler,
                                Exception ex) throws Exception {
    }
}