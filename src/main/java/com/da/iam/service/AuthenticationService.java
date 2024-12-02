package com.da.iam.service;

import com.da.iam.dto.request.LoginRequest;
import com.da.iam.dto.request.LogoutRequest;
import com.da.iam.dto.request.RegisterRequest;
import com.da.iam.dto.response.BasedResponse;
import com.da.iam.dto.response.DefaultTokenResponse;
import com.da.iam.entity.*;
import com.da.iam.exception.UserNotFoundException;
import com.da.iam.repo.*;


import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;

@Service
@RequiredArgsConstructor
public class AuthenticationService implements BaseAuthenticationService {
    private final JWTService jwtService;
    private final UserRepo userRepo;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final EmailService emailService;
    private final RoleRepo roleRepo;
    private final UserRoleRepo userRoleRepo;
    private final PasswordService passwordService;
    private final PasswordResetTokenRepo passwordResetTokenRepo;
    private final BlackListTokenRepo blackListTokenRepo;
    private final UserService userService;

    @Override
    @Transactional
    public BasedResponse<?> register(RegisterRequest request) {
        String email = request.email();
        String password = request.password();
        if (userRepo.existsByEmail(email)) {
            return new BasedResponse().badRequest("Email existed");
        }
        List<UUID> rolesId = getRoles(request.role());//check hop le cac role co trong db ko va tra ve list id cua cac role
        User newUser = User.builder()
                .email(email)
                .password(passwordEncoder.encode(password))
                .build();//khoi tao user

        try {
            userService.save(newUser);//save user
            rolesId.forEach(roleId -> userRoleRepo.saveUserRole(userRepo.getUserIdByEmail(email).orElseThrow(() -> {
                throw new IllegalArgumentException("Error during save user id to user_role table");
            }), roleId));//save role cua user
            var jwtToken = jwtService.generateToken(email);
            var jwtRefreshToken = jwtService.generateRefreshToken(email);
            DefaultTokenResponse tokenResponse = new DefaultTokenResponse(jwtToken, jwtRefreshToken, "Bearer");
            //5 phut hieu luc, trong thoi gian do khong duoc gui them
//          emailService.sendConfirmationRegistrationEmail(request.email(), tokenResponse.getAccessToken());
//          authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, password));
            return new BasedResponse().success("Register successful", newUser);
        } catch (Exception e) {
            throw new IllegalArgumentException("Register failed");
        }
    }

    @Override
    public BasedResponse<?> login(LoginRequest request) {
        String email = request.email();
        String password = request.password();
        User userEntity = userRepo.findByEmail(request.email()).orElseThrow(() -> new UserNotFoundException("User not found"));
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
        var jwtToken = jwtService.generateToken(userEntity.getEmail());
        var jwtRefreshToken = jwtService.generateRefreshToken(userEntity.getEmail());
        DefaultTokenResponse tokenResponse = new DefaultTokenResponse(jwtToken, jwtRefreshToken, "Bearer");
        blackListTokenRepo.save(BlackListToken.builder().token(jwtToken)
                .expirationDate(LocalDateTime.now().plusMinutes(1))
                .userId(userEntity.getUserId())
                .build());
        return new BasedResponse().success("Login successful", tokenResponse);
    }


    private List<UUID> getRoles(Set<String> requestRoles) {
        return requestRoles.stream().map(String::trim)
                .map(roleRepo::findRoleIdByName)
                .map(Optional::orElseThrow)
                .toList();
    }

    @Override
    public <T> BasedResponse<?> getNewAccessToken(String refreshToken) {
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
            //}
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

    @Override
    public <T> BasedResponse<?> getNewAccessToken(T request) {
        return null;
    }

    @Override
    public BasedResponse<?> getNewAccessTokenKeycloak(LogoutRequest request) {
        return null;
    }
}
