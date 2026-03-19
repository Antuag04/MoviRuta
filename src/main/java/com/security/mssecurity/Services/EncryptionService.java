package com.security.mssecurity.Services;

import org.springframework.stereotype.Service;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Service
public class EncryptionService {

    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    public String encryptPassword(String password) {
        return encoder.encode(password);
    }

    public boolean verifyPassword(String rawPassword, String encodedPassword) {
        return encoder.matches(rawPassword, encodedPassword);
    }
}