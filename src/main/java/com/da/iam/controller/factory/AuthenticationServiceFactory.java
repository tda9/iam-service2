package com.da.iam.controller.factory;

<<<<<<<< HEAD:src/main/java/com/da/iam/controller/UserServiceFactory.java
import com.da.iam.service.*;
========
import com.da.iam.service.impl.AuthenticationService;
import com.da.iam.service.BaseAuthenticationService;
import com.da.iam.service.impl.KeycloakAuthenticationService;
>>>>>>>> fixbug/fix-swagger:src/main/java/com/da/iam/controller/factory/AuthenticationServiceFactory.java
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
<<<<<<<< HEAD:src/main/java/com/da/iam/controller/UserServiceFactory.java
public class UserServiceFactory {
    @Value("${application.authProvider}")
    String authProvider ;
    private final UserService userService;
    private final KeycloakUserService keycloakUserService;
    public BaseUserService getUserService() {
        return switch (authProvider) {
            case "DEFAULT" -> userService;
            case "KEYCLOAK" -> keycloakUserService;
========
public class AuthenticationServiceFactory {
    @Value("${application.authProvider}")
    String authProvider ;
    private final AuthenticationService authenticationService;
    private final KeycloakAuthenticationService keycloakAuthenticationService;
    public BaseAuthenticationService getService() {
        return switch (authProvider) {
            case "DEFAULT" -> authenticationService;
            case "KEYCLOAK" -> keycloakAuthenticationService;
>>>>>>>> fixbug/fix-swagger:src/main/java/com/da/iam/controller/factory/AuthenticationServiceFactory.java
            default -> throw new IllegalArgumentException("Invalid service type: " + authProvider);
        };
    }
}
