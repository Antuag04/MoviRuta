package com.security.mssecurity.Services;

import com.security.mssecurity.Models.User;

public record SecurityValidationResult(boolean allowed, int status, String message, User user) {

    public static SecurityValidationResult allowed(User user) {
        return new SecurityValidationResult(true, 200, null, user);
    }

    public static SecurityValidationResult denied(int status, String message) {
        return new SecurityValidationResult(false, status, message, null);
    }
}
