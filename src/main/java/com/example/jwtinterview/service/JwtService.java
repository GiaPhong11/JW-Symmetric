package com.example.jwtinterview.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Controller;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtService {

    @Value("${security.jwt.private-key}")
    private String privateKeyBase64;

    @Value("${security.jwt.public-key}")
    private String publicKeyBase64;

    private PrivateKey privateKey;

    private PublicKey publicKey;

    @PostConstruct
    public void init() throws NoSuchAlgorithmException, InvalidKeySpecException {
        this.privateKey = generatePrivateKey();
        this.publicKey = generatePublicKey();
    }

    private PrivateKey generatePrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        final byte[] privateKeyRaw = Base64.getDecoder().decode(privateKeyBase64);
        final PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyRaw);
        return KeyFactory.getInstance("RSA").generatePrivate(privateKeySpec);
    }

    private PublicKey generatePublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        final byte[] publicKeyRaw = Base64.getDecoder().decode(publicKeyBase64);
        final X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyRaw);
        return KeyFactory.getInstance("RSA").generatePublic(publicKeySpec);
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(publicKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }


    public String generateToken(String userName){
        Map<String,Object> claims=new HashMap<>();
        return createToken(claims,userName);
    }

    private String createToken(Map<String, Object> claims, String userName) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userName)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+ 1000 * 60 * 2))
                .signWith(privateKey, SignatureAlgorithm.RS256).compact();
    }
}
