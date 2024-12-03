package com.da.iam.controller.factory;

<<<<<<<< HEAD:src/main/java/com/da/iam/controller/AuthenticationServiceFactory.java
import com.da.iam.service.AuthenticationService;
import com.da.iam.service.BaseAuthenticationService;
import com.da.iam.service.KeycloakAuthenticationService;
========
import com.da.iam.service.impl.AuthenticationService;
import com.da.iam.service.BaseAuthenticationService;
import com.da.iam.service.impl.KeycloakAuthenticationService;
>>>>>>>> 12df3c1 (raw finish log rolling, search user, swagger integrate):src/main/java/com/da/iam/controller/factory/AuthenticationServiceFactory.java
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
