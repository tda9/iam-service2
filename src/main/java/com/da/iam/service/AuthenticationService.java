package com.da.iam.service;

import com.da.iam.dto.Credentials;
import com.da.iam.dto.request.LoginRequest;
import com.da.iam.dto.request.RegisterRequest;
import com.da.iam.dto.response.BasedResponse;
import com.da.iam.entity.*;
import com.da.iam.exception.TooManyRequestsException;
import com.da.iam.exception.UserNotFoundException;
import com.da.iam.repo.*;


import com.da.iam.utils.InputUtils;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.core.Response;
import lombok.RequiredArgsConstructor;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
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
    @Value("${application.security.jwt.enable}")
    private boolean iamJwtEnabled;

    @Value("${application.security.keycloak.enabled}")
    private boolean keycloakEnabled;


    public BasedResponse<?> register(RegisterRequest request) {

        //check null request, null/empty email, password
        InputUtils.isValidRegisterRequest(request);
        String email = request.email();
        String password = request.password();
        //check email ton tai
        if (userService.getUserByEmail(request.email()).isPresent()) {
            throw new IllegalArgumentException("Email existed");
        }

        User newUser = User.builder().email(email).password(passwordEncoder.encode(password)).build();
        //save user to user table
        userService.saveUser(newUser);
        Set<Role> roles = getRoles(request.role());
        for (Role r : roles) {
            Role role = roleRepo.findRoleByName(r.getName());
            UserRoles userRoles = new UserRoles(newUser.getUserId(), role.getRoleId());
            userRoleRepo.saveUserRole(newUser.getUserId(), userRoles.getRoleId());
        }


        //DEACTIVATE: send email confirm registration here
        //String token = passwordService.generateToken();
        //5 phut hieu luc, trong thoi gian do khong duoc gui them
        //sendConfirmation(request.email(), token, userEntity);
        String jwtToken = null;
        if (iamJwtEnabled) {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, password));
            jwtToken = jwtService.generateToken(newUser.getEmail());
            blackListTokenRepo.save(new BlackListToken(jwtToken, LocalDateTime.now().plusMinutes(10), newUser.getUserId()));
        }
        if (keycloakEnabled) {

            try {
                UsersResource userResource = keycloak().realm("master").users();
                CredentialRepresentation credential = Credentials.createPasswordCredentials(request.password());
                UserRepresentation user = new UserRepresentation();
                user.setUsername(request.email());
                user.setFirstName(null);
                user.setLastName(null);
                user.setEmail(request.email());
                user.setCredentials(Collections.singletonList(credential));
                user.setEnabled(true);
                user.setClientRoles(Map.of());
                userResource.create(user);
            } catch (Exception e) {
                System.out.println(e.getMessage());
            }
        }
        return BasedResponse.builder()
                .httpStatusCode(200)
                .requestStatus(true)
                .data(jwtToken)
                .build();
    }

    public BasedResponse<?> authenticate(LoginRequest request) {
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
        String jwtToken = jwtService.generateToken(userEntity.getEmail());
        blackListTokenRepo.save(new BlackListToken(jwtToken, LocalDateTime.now().plusMinutes(10), userEntity.getUserId()));
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, password));
        return BasedResponse.builder()
                .httpStatusCode(200)
                .requestStatus(true)
                .data(jwtToken)
                .build();
    }

    public Keycloak keycloak() {
        return KeycloakBuilder.builder()
                .serverUrl("http://localhost:8082")
                .realm("master")
                .clientId("iam-service-client-master")
                .grantType("password")
                .scope("openid")
                .clientSecret("x4xQ2O9DsSiGUl1ryd7k8qtXsstWsgxi")
                .authorization("Bearer " + getAccessToken())
                .username("admin")
                .password("admin")
                .build();
    }

    public String getAccessToken() {
        return KeycloakBuilder.builder()
                .serverUrl("http://localhost:8082")
                .realm("master")
                .clientId("iam-service-client-master")
                .grantType("password")
                .username("admin")
                .clientSecret("x4xQ2O9DsSiGUl1ryd7k8qtXsstWsgxi")
                .password("admin")
                .build()
                .tokenManager().getAccessTokenString();
    }

    private Set<Role> getRoles(Set<String> roles) {
        Set<Role> rolesSet = new HashSet<>();
        for (String role : roles) {
            Role tmpRole = new Role();
            tmpRole.setName(role);
            rolesSet.add(tmpRole);
        }
        return rolesSet;
    }
}
