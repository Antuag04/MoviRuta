package com.security.mssecurity.Services;

import com.security.mssecurity.Models.Session;
import com.security.mssecurity.Models.User;
import com.security.mssecurity.Models.UserRole;
import com.security.mssecurity.Repositories.SessionRepository;
import com.security.mssecurity.Repositories.UserRepository;
import com.security.mssecurity.Repositories.UserRoleRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import jakarta.annotation.PostConstruct;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private Long expiration;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserRoleRepository userRoleRepository;

    @Autowired
    private SessionRepository sessionRepository;

    private Key secretKey;

    @PostConstruct
    public void init() {
        if (secret == null || secret.isEmpty()) {
            throw new IllegalArgumentException("jwt.secret no está configurado en application.properties");
        }
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    public String generateToken(User theUser) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expiration);

        Map<String, Object> claims = new HashMap<>();
        claims.put("id", theUser.getId());
        claims.put("name", theUser.getName());
        claims.put("email", theUser.getEmail());
        claims.put("roles", getRoleNames(theUser.getId()));

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(theUser.getId())
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(secretKey, SignatureAlgorithm.HS512)
                .compact();
    }

    public boolean validateToken(String token) {
        try {
            Jws<Claims> claimsJws = parseToken(token);

            Date now = new Date();
            if (claimsJws.getBody().getExpiration().before(now)) {
                return false;
            }

            Session session = sessionRepository.findByToken(token);
            return session != null && !session.getExpiration().before(now);
        } catch (SignatureException ex) {
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    public User getUserFromToken(String token) {
        try {
            if (!validateToken(token)) {
                return null;
            }

            Claims claims = parseToken(token).getBody();
            String userId = (String) claims.get("id");
            return userRepository.findById(userId).orElse(null);
        } catch (Exception e) {
            return null;
        }
    }

    private Jws<Claims> parseToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token);
    }

    private List<String> getRoleNames(String userId) {
        List<UserRole> roles = userRoleRepository.getRolesByUser(userId);
        if (roles == null) {
            return Collections.emptyList();
        }

        return roles.stream()
                .map(UserRole::getRole)
                .filter(role -> role != null && role.getName() != null)
                .map(role -> role.getName())
                .distinct()
                .collect(Collectors.toList());
    }
}
