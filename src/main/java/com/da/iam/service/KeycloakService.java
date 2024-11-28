package com.da.iam.service;

import org.keycloak.admin.client.Keycloak;

import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class KeycloakService {

    @Autowired
    private KeycloakLogoutClient keycloakLogoutClient;

    public void logoutUser(String clientId, String refreshToken, String redirectUri) {
        keycloakLogoutClient.logout(clientId, refreshToken, redirectUri);
    }
}
