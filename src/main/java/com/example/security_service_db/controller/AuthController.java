package com.example.security_service_db.controller;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.*;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/token")
public class AuthController {

    private final AuthenticationManager authenticationManager;

    public AuthController(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    /**
     * Endpoint de login : vérifie username + password en base de données,
     * puis génère un access_token + refresh_token signés avec RSA.
     */
    @PostMapping("/login")
    public Map<String, String> login(@RequestBody Map<String, String> request) throws Exception {
        // Authentification (avec UserDetailsService qui lit depuis la base)
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.get("username"),
                        request.get("password")
                )
        );

        User user = (User) authentication.getPrincipal();

        // Charger la clé privée RSA pour signer le token
        PrivateKey privateKey = getPrivateKey();

        // Récupération des rôles sous forme de chaîne
        String roles = user.getAuthorities().stream()
                .map(grantedAuthority -> grantedAuthority.getAuthority())
                .collect(Collectors.joining(","));

        // Génération du JWT d'accès (valide 2 min)
        String accessToken = Jwts.builder()
                .setSubject(user.getUsername())
                .claim("roles", roles)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 2 * 60 * 1000))
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();

        // Génération du refresh token (valide 10 min)
        String refreshToken = Jwts.builder()
                .setSubject(user.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 10 * 60 * 1000))
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();

        return Map.of(
                "username", user.getUsername(),
                "roles", roles,
                "access_token", accessToken,
                "refresh_token", refreshToken
        );
    }

    /**
     * Endpoint de validation de token (optionnel mais utile pour Postman)
     */
    @GetMapping("/validate")
    public Map<String, Object> validate(@RequestParam String token) {
        try {
            var claims = Jwts.parserBuilder()
                    .build()
                    .parseClaimsJwt(token)
                    .getBody();

            return Map.of(
                    "valid", true,
                    "subject", claims.getSubject(),
                    "roles", claims.get("roles"),
                    "expiration", claims.getExpiration()
            );
        } catch (Exception e) {
            return Map.of("valid", false, "error", e.getMessage());
        }
    }

    /**
     * Lecture de la clé privée RSA depuis le fichier keys/private.pem dans resources
     */
    private PrivateKey getPrivateKey() throws Exception {
        ClassPathResource resource = new ClassPathResource("keys/private.pem");
        try (InputStream is = resource.getInputStream()) {
            String keyContent = new String(is.readAllBytes(), StandardCharsets.UTF_8)
                    .replaceAll("-----BEGIN PRIVATE KEY-----", "")
                    .replaceAll("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] decoded = Base64.getDecoder().decode(keyContent);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(spec);
        }
    }
}