package com.da.iam.service;

import com.da.iam.entity.User;
import com.da.iam.exception.UserNotFoundException;
import com.da.iam.repo.BlackListTokenRepo;
import com.da.iam.repo.UserRepo;
import com.da.iam.utils.RSAKeyUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;
import java.util.function.Function;

@Service
@RequiredArgsConstructor

public class JWTService {
    @Value("${application.security.jwt.expiration}")
    private long jwtExpiration;
    @Value("${application.security.jwt.refresh-token.expiration}")
    private long refreshExpiration;
    @Autowired
    BlackListTokenRepo blackListTokenRepo;
    @Autowired
    UserRepo userRepo;
    public String generateRefreshToken(String username) {
        PrivateKey privateKey = rsaKeyUtil.getPrivateKey();
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date()).setExpiration(new Date(System.currentTimeMillis() + refreshExpiration))
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();
    }
    public String generateToken(String username) {
        PrivateKey privateKey = rsaKeyUtil.getPrivateKey();
        return Jwts.builder().setSubject(username).setIssuedAt(new Date()).setExpiration(new Date(System.currentTimeMillis() + 1000*60*1))//10 phut
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();
    }

    private final RSAKeyUtil rsaKeyUtil;

    public Claims extractAllClaims(String token) throws Exception {
        PublicKey publicKey = rsaKeyUtil.getPublicKey();
        return Jwts.parserBuilder().setSigningKey(publicKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimResolver) throws Exception {
        final Claims claims = extractAllClaims(token);
        return claimResolver.apply(claims);
    }

    public String extractEmail(String jwt) throws Exception {
        return extractClaim(jwt, Claims::getSubject);
    }

    private Date extractExpiration(String token) throws Exception {
        return extractClaim(token, Claims::getExpiration);
    }

    private boolean isTokenExpired(String token) throws Exception {
        return extractExpiration(token).before(new Date());
    }

    public boolean isTokenValid(String token, UserDetails userDetails) throws Exception {
        User u = userRepo.findByEmail(userDetails.getUsername()).orElseThrow(()->new UserNotFoundException("User not found"));
        if (!blackListTokenRepo.findTopByUserIdOrderByCreatedDateDesc(u.getUserId()).get().getToken().equals(token)) {
            return false;
        }
        final String email = extractEmail(token);
        return (email.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }
    public boolean isRefreshTokenValid(String token) throws Exception {
        final String email = extractEmail(token);
        userRepo.findByEmail(email).orElseThrow(()->new UserNotFoundException("User not found"));
        return !isTokenExpired(token);
    }

}
