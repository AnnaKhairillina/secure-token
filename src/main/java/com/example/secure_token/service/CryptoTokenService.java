package com.example.secure_token.service;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.ObjectMapper;

@Service
public class CryptoTokenService {

    private final byte[] ENCRYPTION_KEY;
    private final byte[] HMAC_KEY;
    private static final ObjectMapper mapper = new ObjectMapper();

    public CryptoTokenService(
            @Value("${crypto.encryption-key}") String encryptionKeyBase64,
            @Value("${crypto.hmac-key}") String hmacKeyBase64
    ) {
        this.ENCRYPTION_KEY = Base64.getDecoder().decode(encryptionKeyBase64);
        this.HMAC_KEY = Base64.getDecoder().decode(hmacKeyBase64);
    }

    public String encryptAndSign(String token) throws Exception {
        if (token == null || token.trim().isEmpty()) {
            throw new IllegalArgumentException("Token cannot be null or empty");
        }

        byte[] iv = new byte[16];
        SecureRandom.getInstanceStrong().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(ENCRYPTION_KEY, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        byte[] ciphertext = cipher.doFinal(token.getBytes());

        Mac hmac = Mac.getInstance("HmacSHA256");
        SecretKeySpec hmacKey = new SecretKeySpec(HMAC_KEY, "HmacSHA256");
        hmac.init(hmacKey);
        byte[] hmacBytes = hmac.doFinal(concat(iv, ciphertext));

        Map<String, String> jsonMap = Map.of(
                "iv", Base64.getEncoder().encodeToString(iv),
                "ciphertext", Base64.getEncoder().encodeToString(ciphertext),
                "hmac", Base64.getEncoder().encodeToString(hmacBytes)
        );

        return mapper.writeValueAsString(jsonMap);
    }

    public String verifyAndDecrypt(String json) {
        try {
            Map<String, String> jsonMap = mapper.readValue(json, Map.class);
            byte[] iv = Base64.getDecoder().decode(jsonMap.get("iv"));
            byte[] ciphertext = Base64.getDecoder().decode(jsonMap.get("ciphertext"));
            byte[] receivedHmac = Base64.getDecoder().decode(jsonMap.get("hmac"));

            Mac hmac = Mac.getInstance("HmacSHA256");
            SecretKeySpec hmacKey = new SecretKeySpec(HMAC_KEY, "HmacSHA256");
            hmac.init(hmacKey);
            byte[] calculatedHmac = hmac.doFinal(concat(iv, ciphertext));

            if (!MessageDigest.isEqual(calculatedHmac, receivedHmac)) {
                throw new SecurityException("HMAC verification failed!");
            }

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec keySpec = new SecretKeySpec(ENCRYPTION_KEY, "AES");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));
            byte[] decrypted = cipher.doFinal(ciphertext);
            return new String(decrypted).trim();
        } catch (SecurityException e) {
            throw e;
        } catch (Exception e) {
            throw new SecurityException("Failed to decrypt or verify token", e);
        }
    }

    private byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
