package com.example.secure_token.service;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class CryptoTokenServiceTest {

    private CryptoTokenService service;

    @BeforeEach
    void setup() {
        String encKey = Base64.getEncoder().encodeToString("01234567890123456789012345678901".getBytes());
        String hmacKey = Base64.getEncoder().encodeToString("abcdefabcdefabcdefabcdefabcdefab".getBytes());
        service = new CryptoTokenService(encKey, hmacKey);
    }


    @Test
    void encryptAndDecrypt_shouldWork() throws Exception {
        String original = "MY_SECRET_TOKEN_123";
        String secured = service.encryptAndSign(original);
        String decrypted = service.verifyAndDecrypt(secured);
        assertEquals(original, decrypted);
    }

    @Test
    void decrypt_shouldFailIfCiphertextChanged() throws Exception {
        String token = "secure_data";
        String secured = service.encryptAndSign(token);
        String tampered = secured.replaceFirst("ciphertext\":\"(.)", "ciphertext\":\"Z$1");
        assertThrows(SecurityException.class, () -> service.verifyAndDecrypt(tampered));
    }

    @Test
    void decrypt_shouldFailIfIvChanged() throws Exception {
        String token = "secure_data";
        String secured = service.encryptAndSign(token);
        String tampered = secured.replaceFirst("iv\":\"(.)", "iv\":\"X$1");
        assertThrows(SecurityException.class, () -> service.verifyAndDecrypt(tampered));
    }

    @Test
    void decrypt_shouldFailIfHmacChanged() throws Exception {
        String token = "secure_data";
        String secured = service.encryptAndSign(token);
        String tampered = secured.replaceFirst("hmac\":\"(.)", "hmac\":\"Y$1");
        assertThrows(SecurityException.class, () -> service.verifyAndDecrypt(tampered));
    }

    @Test
    void encrypt_shouldFailOnNullOrEmptyToken() {
        assertThrows(IllegalArgumentException.class, () -> service.encryptAndSign(null));
        assertThrows(IllegalArgumentException.class, () -> service.encryptAndSign(""));
        assertThrows(IllegalArgumentException.class, () -> service.encryptAndSign("   "));
    }

    @Test
    void decrypt_shouldFailOnInvalidJson() {
        String brokenJson = "{not valid json}";
        assertThrows(Exception.class, () -> service.verifyAndDecrypt(brokenJson));
    }
}
