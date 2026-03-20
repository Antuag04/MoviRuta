package com.security.mssecurity.Services;


import com.security.mssecurity.Models.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Servicio responsable de la generación y validación de tokens JWT.
 * 
 * JSON Web Token (JWT) es un estándar abierto (RFC 7519) que define una forma
 * compacta y autónoma de transmitir información de forma segura entre partes
 * como un objeto JSON firmado digitalmente.
 * 
 * Este servicio proporciona las siguientes funcionalidades:
 * - Generación de tokens JWT para usuarios autenticados
 * - Validación de tokens (firma y expiración)
 * - Extracción de información del usuario desde el token
 * 
 * El token generado contiene los siguientes claims:
 * - id: Identificador único del usuario
 * - name: Nombre del usuario
 * - email: Correo electrónico del usuario
 * - sub: Subject (ID del usuario)
 * - iat: Fecha de emisión
 * - exp: Fecha de expiración
 * 
 * @see com.security.mssecurity.Services.ValidatorsService
 */
@Service
public class JwtService {

    /**
     * Clave secreta utilizada para firmar los tokens.
     * Debe mantenerse confidencial y no exponerse en el código fuente.
     */
    @Value("${jwt.secret}")
    private String secret;

    /**
     * Tiempo de expiración del token en milisegundos.
     * Configurado en application.properties.
     */
    @Value("${jwt.expiration}")
    private Long expiration;

    /**
     * Clave criptográfica generada para el algoritmo HS512.
     * Se utiliza para firmar y verificar los tokens.
     */
    private Key secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS512);

    /**
     * Genera un token JWT para el usuario especificado.
     * 
     * El token incluye información del usuario en los claims y está
     * firmado digitalmente para garantizar su integridad.
     * 
     * @param theUser Usuario para el cual se genera el token
     * @return Token JWT como String codificado en Base64
     */
    public String generateToken(User theUser) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expiration);
        
        Map<String, Object> claims = new HashMap<>();
        claims.put("id", theUser.getId());
        claims.put("name", theUser.getName());
        claims.put("email", theUser.getEmail());

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(theUser.getId())
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(secretKey)
                .compact();
    }

    /**
     * Valida un token JWT verificando su firma y fecha de expiración.
     * 
     * @param token Token JWT a validar
     * @return true si el token es válido y no ha expirado, false en caso contrario
     */
    public boolean validateToken(String token) {
        try {
            Jws<Claims> claimsJws = Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token);

            Date now = new Date();
            if (claimsJws.getBody().getExpiration().before(now)) {
                return false;
            }

            return true;
        } catch (SignatureException ex) {
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Extrae la información del usuario contenida en un token JWT.
     * 
     * Reconstruye un objeto User a partir de los claims almacenados
     * en el token. Útil para obtener la identidad del usuario sin
     * consultar la base de datos.
     * 
     * @param token Token JWT del cual extraer la información
     * @return Objeto User con los datos del token, o null si el token es inválido
     */
    public User getUserFromToken(String token) {
        try {
            Jws<Claims> claimsJws = Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token);

            Claims claims = claimsJws.getBody();

            User user = new User();
            user.setId((String) claims.get("id"));
            user.setName((String) claims.get("name"));
            user.setEmail((String) claims.get("email"));
            return user;
        } catch (Exception e) {
            return null;
        }
    }
}
