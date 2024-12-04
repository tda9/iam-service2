package com.da.iam.service.impl;

import com.da.iam.dto.request.LoginRequest;
import com.da.iam.dto.request.LogoutRequest;
import com.da.iam.dto.request.RegisterRequest;
import com.da.iam.dto.response.BaseTokenResponse;
import com.da.iam.dto.response.BasedResponse;
import com.da.iam.dto.response.DefaultTokenResponse;
import com.da.iam.entity.*;
import com.da.iam.exception.ErrorResponseException;
import com.da.iam.exception.UserNotFoundException;
import com.da.iam.repo.*;


import com.da.iam.service.BaseAuthenticationService;
import com.da.iam.service.BaseService;
import com.da.iam.service.JWTService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.*;

@Slf4j
@Service
public class AuthenticationService extends BaseService implements BaseAuthenticationService {
    private final PasswordEncoder passwordEncoder;
    private final UserService userService;
    private final UserRoleRepo userRoleRepo;
    private final JWTService jwtService;
    private final BlackListTokenRepo blackListTokenRepo;
    private final AuthenticationManager authenticationManager;

    public AuthenticationService(UserRepo userRepo,
                                 RoleRepo roleRepo,
                                 PasswordEncoder passwordEncoder,
                                 UserService userService,
                                 UserRoleRepo userRoleRepo,
                                 JWTService jwtService,
                                 BlackListTokenRepo blackListTokenRepo,
                                 AuthenticationManager authenticationManager) {
        super(userRepo, roleRepo);
        this.passwordEncoder = passwordEncoder;
        this.userService = userService;
        this.userRoleRepo = userRoleRepo;
        this.jwtService = jwtService;
        this.blackListTokenRepo = blackListTokenRepo;
        this.authenticationManager = authenticationManager;
    }

    @Override
    @Transactional
    public User register(RegisterRequest request) {
        String email = request.email();
        String password = request.password();
        String firstName = request.firstName();
        String lastName = request.lastName();
        String username = request.username();
        checkEmailExisted(email);
        List<UUID> rolesId = getRoles(request.role());
        User newUser = User.builder()//khoi tao user
                .email(email)
                .username(username)
                .firstName(firstName)
                .lastName(lastName)
                .password(passwordEncoder.encode(password))
                .build();
        try {
            User user = userRepo.save(newUser);
            UUID newUserId = userRepo.getUserIdByEmail(email)
                    .orElseThrow(() -> new ErrorResponseException("Internal error during save user id to user_role table"));
            rolesId.forEach(roleId -> userRoleRepo.saveUserRole(newUserId, roleId));
            //5 phut hieu luc, trong thoi gian do khong duoc gui them
            //emailService.sendConfirmationRegistrationEmail(request.email(), tokenResponse.getAccessToken());
            log.info("Register new user: " + user + " " + LocalDateTime.now());
            return user;
        } catch (Exception e) {
            log.error("Error at register "+ LocalDateTime.now());
            throw new ErrorResponseException("Register failed: " + e.getMessage());
        }
    }

    @Value("${application.security.jwt.expiration}")
    private long jwtExpiration;
    @Value("${application.security.jwt.refresh-token.expiration}")
    private long refreshExpiration;

    private DefaultTokenResponse generateDefaultToken(String email, UUID userId) {
        var jwtToken = jwtService.generateToken(email);
        var jwtRefreshToken = jwtService.generateRefreshToken(email);
        DefaultTokenResponse tokenResponse = new DefaultTokenResponse(jwtToken, jwtRefreshToken, "Bearer", jwtExpiration, refreshExpiration);
        blackListTokenRepo.save(BlackListToken.builder().token(jwtToken)
                .expirationDate(LocalDateTime.now().plusMinutes(1))
                .userId(userId)
                .build());
        return tokenResponse;
    }

    @Override
    public BaseTokenResponse login(LoginRequest request) {
        String email = request.email();
        String password = request.password();
        User userEntity = userRepo.findByEmail(request.email())
                .orElseThrow(() -> new UserNotFoundException("User not found during login"));
//        if (!userEntity.isVerified()) {
//            String token = passwordService.generateToken();
//            sendConfirmation(request.email(), token, userEntity);
//            return BasedResponse.builder()
//                    .httpStatusCode(400)
//                    .requestStatus(false)
//                    .data(email)
//                    .message("Email hasn't been confirmed. We send confirmation register to your email. It will expire in 5 minutes")
//                    .build();
//        }
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, password));
        return generateDefaultToken(email, userEntity.getUserId());
    }


    @Override
    public <T> BasedResponse<?> getNewAccessToken(LogoutRequest request) {
        String refreshToken = request.refreshToken();
        ;
        try {
            //UUID id = blackListTokenRepo.findByToken(accessToken).orElseThrow(() -> new IllegalArgumentException("Invalid access token")).getUserId();
            //accesss token moi nhat va con han
//            if (blackListTokenRepo.findTopByUserIdOrderByCreatedDateDesc(id).isPresent()
//                    && jwtService.isTokenValid(accessToken, CustomUserDetails.builder().email(userDetails.getEmail()).build())) {
//                return BasedResponse.builder()
//                        .requestStatus(true)
//                        .httpStatusCode(200)
//                        .message("Access token is still valid")
//                        .data(accessToken)
//                        .build();
//            } else if (blackListTokenRepo.findTopByUserIdOrderByCreatedDateDesc(id).isPresent()
            //&& !jwtService.isTokenValid(accessToken, CustomUserDetails.builder().email(userDetails.getEmail()).build())) {
            if (jwtService.isRefreshTokenValid(refreshToken)) {
                String email = jwtService.extractEmail(refreshToken);
                var newAccessToken = jwtService.generateToken(email);
                UUID id = userRepo.findByEmail(email).orElseThrow().getUserId();
                blackListTokenRepo.save(new BlackListToken(newAccessToken, LocalDateTime.now().plusMinutes(1), id));
                return BasedResponse.builder()
                        .requestStatus(true)
                        .httpStatusCode(200)
                        .message("New access token")
                        .data(newAccessToken)
                        .build();
            }
            return BasedResponse.builder()
                    .requestStatus(true)
                    .httpStatusCode(200)
                    .message("Invalid refresh token")
                    .build();
        } catch (Exception e) {
            throw new IllegalArgumentException(e.getMessage());
        }

    }

    @Transactional//tim hieu tai sao o day can transactional
    public BasedResponse<?> logout(LogoutRequest request) {
        String email = request.email();
        User u = userRepo.findByEmail(email).orElseThrow();
        blackListTokenRepo.deleteAllByUserId(u.getUserId());
        return BasedResponse.builder()
                .requestStatus(false)
                .httpStatusCode(400)
                .message("Logout successful")
                .build();
    }


}
