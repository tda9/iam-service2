package com.da.iam.service;

import com.da.iam.dto.Credentials;
import com.da.iam.dto.request.UpdateUserRequest;
import com.da.iam.exception.ErrorResponseException;
import com.da.iam.repo.BlackListTokenRepo;
import com.da.iam.repo.RoleRepo;
import com.da.iam.repo.UserRepo;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Value;

import java.util.Collections;
import java.util.List;
import java.util.Map;

@Slf4j
public class BaseKeycloakService extends BaseService {
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
    public BaseKeycloakService(Keycloak keycloak,
                               UserRepo userRepo,
                               RoleRepo roleRepo,
                               BlackListTokenRepo blackListTokenRepo,
                               JWTService jwtService
    ) {
        super(userRepo, roleRepo, blackListTokenRepo, jwtService);
        this.keycloak = keycloak;
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

    public void updateKeycloakUser(UpdateUserRequest request, String oldEmail) {
        try {
            UsersResource usersResource = keycloak().realm(realm).users();
            // Use searchByEmail to find the user
            List<UserRepresentation> users = usersResource.searchByEmail(oldEmail, true);
            if (users.isEmpty()) {
                throw new IllegalArgumentException("User with email " + oldEmail + " not found.");
            }
            UserRepresentation userRepresentation = users.get(0);
            userRepresentation.setEnabled(!request.isLock());
            userRepresentation.setEmail(request.email());
            usersResource.get(userRepresentation.getId()).update(userRepresentation);
            log.info("Update both keycloak and iam service successful");
        } catch (Exception ex) {
            log.error(ex.getMessage());
            throw new ErrorResponseException("Failed change keycloak password: " + ex.getMessage());
        }
    }

    public void createKeycloakUser(String email, String password) {
        try {
            UsersResource userResource = keycloak().realm(realm).users();
            CredentialRepresentation credential = Credentials.createPasswordCredentials(password);
            UserRepresentation user = new UserRepresentation();
            user.setUsername(email);
            user.setEmail(email);
            user.setCredentials(Collections.singletonList(credential));
            user.setEnabled(true);
            userResource.create(user);
        } catch (Exception e) {
            throw new ErrorResponseException("Error at class BaseKeycloakService, function createKeycloakUser: " + e.getMessage());
        }
    }
}
