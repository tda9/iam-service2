package com.da.iam.service;

import com.da.iam.dto.Credentials;
import com.da.iam.dto.request.LoginRequest;
import com.da.iam.dto.request.RegisterRequest;
import com.da.iam.dto.response.BasedResponse;
import com.da.iam.dto.response.KeycloakResponse;
import com.da.iam.entity.*;
import com.da.iam.exception.UserNotFoundException;
import com.da.iam.repo.*;


import com.da.iam.utils.InputUtils;
import lombok.RequiredArgsConstructor;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

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
    private final Keycloak keycloak;


    public BasedResponse<?> register(RegisterRequest request) {
        InputUtils.isValidRegisterRequest(request);
        String email = request.email();
        String password = request.password();
        if (userService.getUserByEmail(request.email()).isPresent()) { //check email ton tai
            throw new IllegalArgumentException("Email existed");
        }
        Set<Role> roles = getRoles(request.role());
        User newUser = User.builder().email(email).password(passwordEncoder.encode(password)).build();

        //save user,user's roles to db
        userService.saveUser(newUser);
        for (Role role : roles) {
            UserRoles userRoles = new UserRoles(newUser.getUserId(), role.getRoleId());
            userRoleRepo.saveUserRole(newUser.getUserId(), userRoles.getRoleId());
        }

        //DEACTIVATE: send email confirm registration here
        /*
        String token = passwordService.generateToken();
        5 phut hieu luc, trong thoi gian do khong duoc gui them
        sendConfirmation(request.email(), token, userEntity);
        */

        String accessToken = null;
        if (iamJwtEnabled) {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, password));
            accessToken = jwtService.generateToken(newUser.getEmail());
            blackListTokenRepo.save(new BlackListToken(accessToken, LocalDateTime.now().plusMinutes(10), newUser.getUserId()));
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
                //user.isEmailVerified();
                user.setClientRoles(Map.of());
                userResource.create(user);
            } catch (Exception e) {
                System.out.println(e.getMessage());
            }
//          KeycloakResponse keycloakResponse = new KeycloakResponse(keycloak().tokenManager().getAccessTokenString(),keycloak().tokenManager().)
//          accessToken = getAccessTokenMaster();
        }
        return BasedResponse.builder()
                .httpStatusCode(200)
                .requestStatus(true)
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
        Object tokenResponse = null;
        if (iamJwtEnabled) {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, password));
            tokenResponse = jwtService.generateToken(userEntity.getEmail());
            blackListTokenRepo.save(new BlackListToken(tokenResponse.toString(), LocalDateTime.now().plusMinutes(10), userEntity.getUserId()));
        }
        if (keycloakEnabled) {
            try {
                tokenResponse = getKeycloakUserToken(email, password);
            } catch (Exception e) {
                System.out.println(e.getMessage());
            }

        }
        return BasedResponse.builder()
                .httpStatusCode(200)
                .requestStatus(true)
                .data(tokenResponse)
                .build();
    }

    public Keycloak keycloak() {
        return KeycloakBuilder.builder()
                .serverUrl(serverUrl)
                .realm(realm)
                .clientId(clientId)
                .grantType(grantType)
                .authorization("Bearer " + getAccessTokenMaster())
                .username(username)
                .clientSecret(clientSecret)
                .password(password)
                .build();
    }

    public String getAccessTokenMaster() {
        return keycloak.tokenManager().getAccessTokenString();
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

    public KeycloakResponse getKeycloakUserToken(String username, String password) {
        String tokenUrl = "http://localhost:8082/realms/master/protocol/openid-connect/token";
        RestTemplate restTemplate = new RestTemplate();
        // Set headers
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.CONTENT_TYPE, "application/x-www-form-urlencoded");

        // Set body response
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "password");
        body.add("client_id", "iam-service-client-master"); // Replace with your Keycloak client ID
        //body.add("client_secret", "your-client-secret"); // Replace with your Keycloak client secret
        //body.add("client_secret", "your-client-secret"); // Replace with your Keycloak client secret
        body.add("username", username);
        body.add("password", password);

        // Create the request
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);
        // Send the request
        ResponseEntity<KeycloakResponse> response = restTemplate.exchange(tokenUrl, HttpMethod.POST, request, KeycloakResponse.class);
        return response.getBody();
    }

    @Value("${application.security.keycloak.serverUrl}")
    private String serverUrl;
    @Value("${application.security.keycloak.realm}")
    private String realm;
    @Value("${application.security.keycloak.clientId}")
    private String clientId;
    @Value("${application.security.keycloak.clientSecret}")
    private String clientSecret;
    @Value("${application.security.keycloak.grantType}")
    private String grantType;
    @Value("${application.security.keycloak.username}")
    private String username;
    @Value("${application.security.keycloak.password}")
    private String password;
}
