package com.example.secure_token.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.secure_token.service.CryptoTokenService;

@RestController
@RequestMapping("/api/token")
public class TokenController {

    private final CryptoTokenService cryptoTokenService;

    public TokenController(CryptoTokenService cryptoTokenService) {
        this.cryptoTokenService = cryptoTokenService;
    }

    @PostMapping("/encrypt")
    public ResponseEntity<?> encryptToken(@RequestBody String plainToken) {
        try {
            String secured = cryptoTokenService.encryptAndSign(plainToken);
            return ResponseEntity.ok(secured);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body("Ошибка шифрования: " + e.getMessage());
        }
    }

    @PostMapping("/decrypt")
    public ResponseEntity<?> decryptToken(@RequestBody String securedJson) {
        try {
            String token = cryptoTokenService.verifyAndDecrypt(securedJson);
            return ResponseEntity.ok("Токен расшифрован: " + token);
        } catch (SecurityException e) {
            return ResponseEntity.badRequest().body("Подделанный токен.");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Ошибка: " + e.getMessage());
        }
    }
}
