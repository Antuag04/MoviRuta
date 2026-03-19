package com.security.mssecurity.Models;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Data
@Document
public class Permission {
    @Id
    private String id;
    private String url;        // ej: "/users"
    private String method;     // ej: "GET", "POST", "PUT", "DELETE"
    private String model;      // ej: "Vehicle", "User", es la entidad a la que pertenece

    public Permission() {
    }

    public Permission(String url, String method, String model) {
        this.url = url;
        this.method = method;
        this.model = model;
    }
}