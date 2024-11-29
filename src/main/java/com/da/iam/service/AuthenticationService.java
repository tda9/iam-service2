package com.da.iam.service;

import com.da.iam.dto.request.LoginRequest;
import com.da.iam.dto.request.LogoutDto;
import com.da.iam.dto.request.RegisterRequest;
import com.da.iam.dto.response.BasedResponse;
import com.da.iam.entity.*;
import com.da.iam.exception.UserNotFoundException;
import com.da.iam.repo.*;


import com.da.iam.utils.InputUtils;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.keycloak.admin.client.Keycloak;
import org.springframework.beans.factory.annotation.Value;
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
public class AuthenticationService implements BaseService{
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

    @Value("${application.security.keycloak.enabled}")
    private String authProvider;
    private final Keycloak keycloak;
    private final KeycloakService keycloakService;
    @Override
    public BasedResponse<?> register(RegisterRequest request) {
        InputUtils.isValidRegisterRequest(request);
        String email = request.email();
        String password = request.password();
        if (userService.getUserByEmail(request.email()).isPresent()) { //check email ton tai
            throw new IllegalArgumentException("Email existed");
        }
        Set<Role> roles = getRoles(request.role());//check hop le cac role co trong db ko
        User newUser = User.builder().email(email).password(passwordEncoder.encode(password)).build();//khoi tao user

        userService.saveUser(newUser);//save user
        for (Role role : roles) {//save role cua user
            UserRoles userRoles = new UserRoles(newUser.getUserId(), role.getRoleId());
            userRoleRepo.saveUserRole(newUser.getUserId(), userRoles.getRoleId());
        }

        /*
        //DEACTIVATE: send email confirm registration here
        String token = passwordService.generateToken();
        //5 phut hieu luc, trong thoi gian do khong duoc gui them
        sendConfirmation(request.email(), token, userEntity);
        */

        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, password));
        return BasedResponse.builder()
                .httpStatusCode(200)
                .requestStatus(true)
                .build();
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
        blackListTokenRepo.save(BlackListToken.builder().token(jwtToken)
                .expirationDate(LocalDateTime.now().plusMinutes(10))
                .userId(userEntity.getUserId())
                .build());
        return BasedResponse.builder()
                .httpStatusCode(200)
                .requestStatus(true)
                .data(jwtToken)
                .message(jwtRefreshToken)
                .build();
    }


    private Set<Role> getRoles(Set<String> roles) {
        Set<Role> rolesSet = new HashSet<>();
        for (String r : roles) {
            Role role = roleRepo.findRoleByName(r);
            if (role == null || role.isDeleted()) {
                throw new IllegalArgumentException("There is role that was deleted");
            }
            rolesSet.add(role);
        }
        return rolesSet;
    }
    @Override
    public <T> BasedResponse<?> getNewAccessToken(HttpServletRequest request) {
        final String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String refreshToken;
        final String email;

        //skip if the request does not have a JWT token
        if (header == null || !header.startsWith("Bearer ")) {
            return BasedResponse.builder()
                    .requestStatus(false)
                    .httpStatusCode(400)
                    .message("Token not found")
                    .build();
        }
        refreshToken = header.substring(7);
        try {
            email = jwtService.extractEmail(refreshToken);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        //check if the email is not null and the user is not authenticated
        if (email != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            var userDetails = userRepo.findByEmail(email).orElseThrow(() -> new UserNotFoundException("User not found"));
            try {
                if (jwtService.isTokenValid(refreshToken, CustomUserDetails.builder().email(email).build())) {
                    var accessToken = jwtService.generateToken(email);
                    //blackListTokenRepo.save(new BlackListToken(accessToken, LocalDateTime.now().plusMinutes(10), LocalDateTime.now(), userDetails.getUserId()));
//                    response.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);
//                    response.setHeader(HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS, HttpHeaders.AUTHORIZATION);
                   //new ObjectMapper().writeValue(response.getOutputStream(),
                    return  BasedResponse.builder()
                            .requestStatus(true)
                            .httpStatusCode(200)
                            .message(refreshToken)
                            .data(accessToken)
                            .build();
                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        return null;
    }
    @Transactional//tim hieu tai sao o day can transactional
    public BasedResponse<?> logout(LogoutDto logoutDto) {
        String email = logoutDto.email();
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
    public BasedResponse<?> getNewAccessTokenKeycloak(LogoutDto logoutDto) {
        return null;
    }
}
