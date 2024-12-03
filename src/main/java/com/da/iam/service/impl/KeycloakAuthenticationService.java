package com.da.iam.service.impl;

import com.da.iam.dto.Credentials;
import com.da.iam.dto.request.LoginRequest;
import com.da.iam.dto.request.LogoutRequest;
import com.da.iam.dto.request.RegisterRequest;
import com.da.iam.dto.response.BaseTokenResponse;
import com.da.iam.dto.response.BasedResponse;
import com.da.iam.dto.response.KeycloakTokenResponse;

import com.da.iam.entity.PasswordResetToken;
import com.da.iam.entity.User;
import com.da.iam.exception.ErrorResponseException;
import com.da.iam.exception.TooManyRequestsException;
import com.da.iam.exception.UserNotFoundException;
import com.da.iam.repo.PasswordResetTokenRepo;
import com.da.iam.repo.RoleRepo;
import com.da.iam.repo.UserRepo;
import com.da.iam.repo.UserRoleRepo;
import com.da.iam.service.BaseAuthenticationService;
import com.da.iam.service.BaseService;
import com.da.iam.service.EmailService;
import com.da.iam.service.PasswordService;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
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
public class KeycloakAuthenticationService extends BaseService implements BaseAuthenticationService {
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
    @Value("${application.security.keycloak.logoutUrl}")
    private String LOGOUT_URL;
    @Value("${application.security.keycloak.newAccessTokenUrl}")
    private String NEW_ACCESS_TOKEN_URL;
    private final Keycloak keycloak;
    private final PasswordService passwordService;
    private final AuthenticationManager authenticationManager;
    private final UserRepo userRepo;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationService authenticationService;
    private final EmailService emailService;
    private final PasswordResetTokenRepo passwordResetTokenRepo;

    public KeycloakAuthenticationService(UserRepo userRepo,
                                         RoleRepo roleRepo,
                                         Keycloak keycloak,
                                         PasswordService passwordService,
                                         AuthenticationManager authenticationManager,
                                         UserRepo userRepo1, UserService userService,
                                         UserRoleRepo userRoleRepo,
                                         PasswordEncoder passwordEncoder,
                                         AuthenticationService authenticationService,
                                         EmailService emailService,
                                         PasswordResetTokenRepo passwordResetTokenRepo) {
        super(userRepo, roleRepo);
        this.keycloak = keycloak;
        this.passwordService = passwordService;
        this.authenticationManager = authenticationManager;
        this.userRepo = userRepo1;
        this.passwordEncoder = passwordEncoder;
        this.authenticationService = authenticationService;
        this.emailService = emailService;
        this.passwordResetTokenRepo = passwordResetTokenRepo;
    }

    @Override
    public User register(RegisterRequest request) {
        try {
            User user = authenticationService.register(request);
            createKeycloakUser(user.getEmail(), user.getPassword());
            return user;
        } catch (Exception e) {
            throw new IllegalArgumentException("Register with keycloak failed");
        }
    }

    public void createKeycloakUser(String username, String password) {
        try {
            UsersResource userResource = keycloak().realm(realm).users();
            CredentialRepresentation credential = Credentials.createPasswordCredentials(password);
            UserRepresentation user = new UserRepresentation();
            user.setUsername(username);
            user.setFirstName(null);
            user.setLastName(null);
            user.setEmail(username);
            user.setCredentials(Collections.singletonList(credential));
            user.setEnabled(true);
            //user.isEmailVerified();
            user.setClientRoles(Map.of());
            userResource.create(user);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    @Override
    public BaseTokenResponse login(LoginRequest request) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.email(), request.password()));
        try {
            authenticationService.login(request);
            return getKeycloakUserToken(request.email(), request.password());
        } catch (Exception e) {
            throw new IllegalArgumentException("Login with keycloak failed");
        }
    }

    public void changePassword(String currentPassword, String newPassword, String confirmPassword, String email) {
        User user = userRepo.findByEmail(email).orElseThrow(() -> new UserNotFoundException("User not found"));
        if (!newPassword.equals(confirmPassword)) {
            throw new IllegalArgumentException("Passwords do not match");
        }
        if (!passwordEncoder.matches(currentPassword, user.getPassword())) {
            throw new IllegalArgumentException("Current password is incorrect");
        }
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepo.save(user);

        try {
            UsersResource usersResource = keycloak.realm(realm).users();
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

    @Override
    public BasedResponse<?> logout(LogoutRequest logoutDto) {
        String refreshToken = logoutDto.refreshToken();
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
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        // Send the request
        ResponseEntity<String> response = restTemplate.exchange(
                LOGOUT_URL,
                HttpMethod.POST,
                request,
                String.class
        );

        // Check response status
        if (response.getStatusCode().is2xxSuccessful()) {
            System.out.println("Logout successful!");
        } else {
            System.out.println("Logout failed: " + response.getStatusCode());
        }
        return BasedResponse.builder()
                .requestStatus(false)
                .httpStatusCode(400)
                .message("Logout successful")
                .build();
    }



    @Override
    public BasedResponse<?> getNewAccessToken(LogoutRequest logoutDto) {
        String refreshToken = logoutDto.refreshToken();
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
        return BasedResponse.builder()
                .requestStatus(true)
                .httpStatusCode(200)
                .data(response.getBody())
                .build();
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


    public void forgotPassword(String to) {
        User user = userRepo.findByEmail(to).orElseThrow();
        Optional<PasswordResetToken> lastToken = passwordResetTokenRepo.findTopByUserIdOrderByCreatedDateDesc(user.getUserId());
        if (lastToken.isPresent() && lastToken.get().getExpirationDate().isAfter(LocalDateTime.now())) {
            throw new TooManyRequestsException("You can only request a password reset every 5 minutes.");
        } else if (lastToken.isPresent() && lastToken.get().getExpirationDate().isBefore(LocalDateTime.now())) {
            passwordResetTokenRepo.delete(lastToken.get());
        }
        String token = passwordService.generateToken();
        //emailService.sendEmail(to, "Confirm password reset", "Your token is:"+ token);
        emailService.sendResetPassword(to, "Confirm password reset", "ResetPasswordTemplate.html", token);
        passwordResetTokenRepo.save(new PasswordResetToken(token, LocalDateTime.now().plusMinutes(5), user.getUserId()));
    }

    public void resetPassword(String email, String newPassword, String token) {
        User user = userRepo.findByEmail(email).orElseThrow();
        PasswordResetToken requestToken = passwordResetTokenRepo.findPasswordResetTokenByToken(token);
        if (requestToken.getExpirationDate().isBefore(LocalDateTime.now()) || !Objects.equals(user.getUserId(), requestToken.getUserId())) {
            throw new IllegalArgumentException("Invalid or expired token");
        }
        user.setPassword(passwordEncoder.encode(newPassword));


        userRepo.save(user);
        passwordResetTokenRepo.delete(requestToken);
        try {
            UsersResource usersResource = keycloak.realm(realm).users();
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
