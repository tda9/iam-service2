package com.da.iam.service;

import com.da.iam.dto.Credentials;
import com.da.iam.dto.request.LoginRequest;
import com.da.iam.dto.request.LogoutDto;
import com.da.iam.dto.request.RegisterRequest;
import com.da.iam.dto.response.BasedResponse;
import com.da.iam.dto.response.KeycloakResponse;

import com.da.iam.entity.Role;
import com.da.iam.entity.User;
import com.da.iam.entity.UserRoles;
import com.da.iam.exception.UserNotFoundException;
import com.da.iam.repo.RoleRepo;
import com.da.iam.repo.UserRepo;
import com.da.iam.repo.UserRoleRepo;
import com.da.iam.utils.InputUtils;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
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

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@RequiredArgsConstructor
@Service
public class KeycloakService implements BaseService {
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
    private final AuthenticationManager authenticationManager;
    private final UserRepo userRepo;
    private final UserService userService;
    private final RoleRepo roleRepo;
    private final UserRoleRepo userRoleRepo;
    private final PasswordEncoder passwordEncoder;
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
        try {
            UsersResource userResource = keycloak().realm("master").users();
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
        Object tokenResponse = null;
        try {
            tokenResponse = getKeycloakUserToken(email, password);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        return BasedResponse.builder()
                .httpStatusCode(200)
                .requestStatus(true)
                .data(tokenResponse)
                .build();
    }

    @Override
    public <T> BasedResponse<?> getNewAccessToken(HttpServletRequest request) {
        return null;
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
    public BasedResponse<?> logout(LogoutDto logoutDto) {
        String refreshToken = logoutDto.refreshToken();
        RestTemplate restTemplate = new RestTemplate();

        // Set headers
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.CONTENT_TYPE, "application/x-www-form-urlencoded");

        // Set body with required parameters
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("client_id", "iam-service-client-master");
        //body.add("client_secret", ""); // Replace with your Keycloak client secret
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
    public <T> BasedResponse<?> getNewAccessToken(T request) {
        return null;
    }

    @Override
    public BasedResponse<?> getNewAccessTokenKeycloak(LogoutDto logoutDto) {
        String refreshToken = logoutDto.refreshToken();
        RestTemplate restTemplate = new RestTemplate();

        // Set headers
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.CONTENT_TYPE, "application/x-www-form-urlencoded");

        // Set body with required parameters
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("client_id", "iam-service-client-master");
        //body.add("client_secret", ""); // Replace with your Keycloak client secret
        body.add("refresh_token", refreshToken);
        body.add("grant_type", "refresh_token");
        // Create the request
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        // Send the request
        ResponseEntity<KeycloakResponse> response = restTemplate.exchange(
                NEW_ACCESS_TOKEN_URL,
                HttpMethod.POST,
                request,
                KeycloakResponse.class
        );

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
}
