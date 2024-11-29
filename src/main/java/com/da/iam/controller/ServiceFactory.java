package com.da.iam.controller;

import com.da.iam.service.AuthenticationService;
import com.da.iam.service.BaseService;
import com.da.iam.service.KeycloakService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class ServiceFactory {
    @Value("${application.authProvider}")
    String authProvider ;
    private final AuthenticationService authenticationService;
    private final KeycloakService keycloakService;
    public BaseService getService() {
        return switch (authProvider) {
            case "DEFAULT" -> authenticationService;
            case "KEYCLOAK" -> keycloakService;
            default -> throw new IllegalArgumentException("Invalid service type: " + authProvider);
        };
    }

}
