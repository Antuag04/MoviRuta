package com.security.mssecurity.Models;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;


@Data
@Document
public class User {
    @Id
    private String id;
    private String name;
    private String email;
    private String password;
    
    // Campo para saber cómo se registró el usuario: "LOCAL" o "GOOGLE"
    private String authProvider;


    public User() {
    }

    public User(String name, String email, String password) {
        this.name = name;
        this.email = email;
        this.password = password;
        this.authProvider = "LOCAL"; // Por defecto, registro tradicional
    }
    
    // Constructor para usuarios de Google (sin password)
    public User(String name, String email, String authProvider, boolean isOAuth) {
        this.name = name;
        this.email = email;
        this.password = null; // Los usuarios de Google NO tienen password
        this.authProvider = authProvider;
    }
}
