package com.example.security_service_db.service;

import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Service
public class KeyLoaderService {

    private PublicKey publicKey;
    private PrivateKey privateKey;

    public KeyLoaderService() {
        try {
            loadKeys();
        } catch (Exception e) {
            throw new RuntimeException("Failed to load RSA keys", e);
        }
    }

    private void loadKeys() throws Exception {
        // Charger la clé publique depuis src/main/resources/keys/public.pem
        InputStream pubFile = new ClassPathResource("keys/public.pem").getInputStream();
        String pubKeyContent = new String(pubFile.readAllBytes())
                .replaceAll("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(pubKeyContent));
        this.publicKey = KeyFactory.getInstance("RSA").generatePublic(pubKeySpec);

        // Charger la clé privée depuis src/main/resources/keys/private.pem
        InputStream privFile = new ClassPathResource("keys/private.pem").getInputStream();
        String privKeyContent = new String(privFile.readAllBytes())
                .replaceAll("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privKeyContent));
        this.privateKey = KeyFactory.getInstance("RSA").generatePrivate(privKeySpec);
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }
}
