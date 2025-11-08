package com.example.security_service_db.controller;

import com.example.security_service_db.service.KeyLoaderService;

import io.jsonwebtoken.Jwts;

import io.jsonwebtoken.SignatureAlgorithm;

import org.springframework.security.authentication.AuthenticationManager;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import org.springframework.security.core.Authentication;

import org.springframework.security.core.GrantedAuthority;

import org.springframework.security.core.userdetails.User;

import org.springframework.web.bind.annotation.*;

import java.util.Date;

import java.util.Map;

import java.util.stream.Collectors;

@RestController

@RequestMapping("/token")

public class AuthController {

    private final AuthenticationManager authenticationManager;

    private final KeyLoaderService keyLoaderService;

    public AuthController(AuthenticationManager authenticationManager, KeyLoaderService keyLoaderService) {

        this.authenticationManager = authenticationManager;

        this.keyLoaderService = keyLoaderService;

    }



    @PostMapping("/login")

    public Map<String, String> login(@RequestBody Map<String, String> request) {


        Authentication authentication = authenticationManager.authenticate(

                new UsernamePasswordAuthenticationToken(

                        request.get("username"),

                        request.get("password")

                )

        );

        User user = (User) authentication.getPrincipal();

        String roles = user.getAuthorities().stream()

                .map(GrantedAuthority::getAuthority)

                .collect(Collectors.joining(","));

        String accessToken = Jwts.builder()

                .setSubject(user.getUsername())

                .claim("roles", roles)

                .setIssuedAt(new Date())

                .setExpiration(new Date(System.currentTimeMillis() + 2 * 60 * 1000))

                .signWith(keyLoaderService.getPrivateKey(), SignatureAlgorithm.RS256)

                .compact();


        String refreshToken = Jwts.builder()

                .setSubject(user.getUsername())

                .setIssuedAt(new Date())

                .setExpiration(new Date(System.currentTimeMillis() + 10 * 60 * 1000))

                .signWith(keyLoaderService.getPrivateKey(), SignatureAlgorithm.RS256)

                .compact();

        return Map.of(

                "username", user.getUsername(),

                "roles", roles,

                "access_token", accessToken,

                "refresh_token", refreshToken

        );

    }

    /**

     * Endpoint de validation de token

     */

    @GetMapping("/validate")

    public Map<String, Object> validate(@RequestParam String token) {

        try {

            var claims = Jwts.parserBuilder()

                    .setSigningKey(keyLoaderService.getPublicKey())  // Utilisation de la clé publique

                    .build()

                    .parseClaimsJws(token)

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

}
