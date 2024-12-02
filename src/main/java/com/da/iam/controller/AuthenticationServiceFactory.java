package com.da.iam.controller;

import com.da.iam.service.AuthenticationService;
import com.da.iam.service.BaseAuthenticationService;
import com.da.iam.service.KeycloakAuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class AuthenticationServiceFactory {
    @Value("${application.authProvider}")
    String authProvider ;
    private final AuthenticationService authenticationService;
    private final KeycloakAuthenticationService keycloakAuthenticationService;
    public BaseAuthenticationService getService() {
        return switch (authProvider) {
            case "DEFAULT" -> authenticationService;
            case "KEYCLOAK" -> keycloakAuthenticationService;
            default -> throw new IllegalArgumentException("Invalid service type: " + authProvider);
        };
    }

}
