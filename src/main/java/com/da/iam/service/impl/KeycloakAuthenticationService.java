package com.da.iam.service.impl;

import com.da.iam.dto.request.LoginRequest;
import com.da.iam.dto.request.LogoutRequest;
import com.da.iam.dto.request.RegisterRequest;
import com.da.iam.dto.response.BaseTokenResponse;
import com.da.iam.dto.response.BasedResponse;
import com.da.iam.dto.response.KeycloakTokenResponse;

import com.da.iam.entity.User;
import com.da.iam.exception.ErrorResponseException;
import com.da.iam.repo.*;
import com.da.iam.service.*;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.*;


@Service
@Slf4j
public class KeycloakAuthenticationService extends BaseKeycloakService implements BaseAuthenticationService {
    private final PasswordService passwordService;

    private final AuthenticationService authenticationService;

    @Value("${application.security.keycloak.realm}")
    private String realm;
    @Value("${application.security.keycloak.clientId}")
    private String clientId;
    @Value("${application.security.keycloak.serverUrl}")
    private String serverUrl;
    @Value("${application.security.keycloak.logoutUrl}")
    private String LOGOUT_URL;
    @Value("${application.security.keycloak.newAccessTokenUrl}")
    private String NEW_ACCESS_TOKEN_URL;
    public KeycloakAuthenticationService(UserRepo userRepo,
                                         RoleRepo roleRepo,
                                         Keycloak keycloak,
                                         PasswordService passwordService,
                                         AuthenticationService authenticationService,
                                         BlackListTokenRepo blackListTokenRepo,
                                         JWTService jwtService
                                         ) {
        super(keycloak,userRepo, roleRepo,blackListTokenRepo,jwtService);
        this.passwordService = passwordService;
        this.authenticationService = authenticationService;
    }

    @Override
    public User register(RegisterRequest request) {
        try {
            User user = authenticationService.register(request);
            createKeycloakUser(request.email(), request.password());
            return user;
        } catch (Exception e) {
            throw new IllegalArgumentException("Register with keycloak failed");
        }
    }


    @Override
    public BaseTokenResponse login(LoginRequest request) {
        try {
            authenticationService.login(request);
            return getKeycloakUserToken(request.email(), request.password());
        } catch (Exception e) {
            throw new IllegalArgumentException("Login with keycloak failed");
        }
    }
@Override
    public void changePassword(String currentPassword, String newPassword, String confirmPassword, String email) {
        passwordService.changePassword(currentPassword, newPassword, confirmPassword, email);
        try {
            UsersResource usersResource = keycloak().realm(realm).users();
            // Use searchByEmail to find the user
            List<UserRepresentation> users = usersResource.searchByEmail(email, true);
            if (users.isEmpty()) {
                throw new IllegalArgumentException("User with email " + email + " not found.");
            }
            UserRepresentation userRepresentation = users.get(0);
            String userId = userRepresentation.getId();
            CredentialRepresentation credential = new CredentialRepresentation();
            credential.setType(CredentialRepresentation.PASSWORD);
            credential.setValue(newPassword);
            credential.setTemporary(false);
            UserResource userResource = usersResource.get(userId);
            userResource.resetPassword(credential);
        } catch (Exception ex) {
            throw new ErrorResponseException("Failed change keycloak password: " + ex.getMessage());
        }
    }


    @Override
    public void logout(LogoutRequest request) {
        String refreshToken = request.refreshToken();
        RestTemplate restTemplate = new RestTemplate();

        // Set headers
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.CONTENT_TYPE, "application/x-www-form-urlencoded");

        // Set body
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("client_id", clientId);
        //body.add("client_secret", clientSecret);
        body.add("refresh_token", refreshToken);
        // Create the request
        HttpEntity<MultiValueMap<String, String>> requestKeycloak = new HttpEntity<>(body, headers);
        // Send the request
        ResponseEntity<String> response = restTemplate.exchange(
                LOGOUT_URL,
                HttpMethod.POST,
                requestKeycloak,
                String.class
        );

        // Check response status
        if (response.getStatusCode().is2xxSuccessful()) {
            System.out.println("Logout successful!");
        } else {
            System.out.println("Logout failed: " + response.getStatusCode());
        }
        BasedResponse.success("Logout successful", request.email());
    }


    @Override
    public BaseTokenResponse refreshToken(String  refreshToken) {
        RestTemplate restTemplate = new RestTemplate();
        // Set headers
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.CONTENT_TYPE, "application/x-www-form-urlencoded");

        // Set body with required parameters
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("client_id", clientId);
        //body.add("client_secret", ""); // Replace with your Keycloak client secret
        body.add("refresh_token", refreshToken);
        body.add("grant_type", "refresh_token");
        // Create the request
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        // Send the request
        ResponseEntity<KeycloakTokenResponse> response = restTemplate.exchange(NEW_ACCESS_TOKEN_URL, HttpMethod.POST, request, KeycloakTokenResponse.class);
        // Check response status
        if (response.getStatusCode().is2xxSuccessful()) {
            System.out.println("Logout successful!");
        } else {
            System.out.println("Logout failed: " + response.getStatusCode());
        }
        return response.getBody();
    }

    public KeycloakTokenResponse getKeycloakUserToken(String username, String password) {
        String tokenUrl = serverUrl + "/realms/" + realm + "/protocol/openid-connect/token";
        RestTemplate restTemplate = new RestTemplate();
        // Set headers
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.CONTENT_TYPE, "application/x-www-form-urlencoded");

        // Set body
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "password");
        body.add("client_id", clientId);
        //body.add("client_secret", clientSecret);
        body.add("username", username);
        body.add("password", password);

        // Create the request
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);
        // Send the request
        ResponseEntity<KeycloakTokenResponse> response = restTemplate.exchange(tokenUrl, HttpMethod.POST, request, KeycloakTokenResponse.class);
        return response.getBody();
    }

    @Override
    public void resetPassword(String email, String newPassword, String token) {
        passwordService.resetPassword(email, newPassword, token);
        try {
            UsersResource usersResource = keycloak().realm(realm).users();
            // Use searchByEmail to find the user
            List<UserRepresentation> users = usersResource.searchByEmail(email, true);
            if (users.isEmpty()) {
                throw new IllegalArgumentException("User with email " + email + " not found.");
            }
            UserRepresentation userRepresentation = users.get(0);
            String userId = userRepresentation.getId();
            CredentialRepresentation credential = new CredentialRepresentation();
            credential.setType(CredentialRepresentation.PASSWORD);
            credential.setValue(newPassword);
            credential.setTemporary(false);
            UserResource userResource = usersResource.get(userId);
            userResource.resetPassword(credential);
        } catch (Exception ex) {
            throw new ErrorResponseException("Failed reset keycloak password: " + ex.getMessage());
        }
    }

}
