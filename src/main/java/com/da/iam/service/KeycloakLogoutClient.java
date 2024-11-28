package com.da.iam.service;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@FeignClient(name = "keycloak-client", url = "http://localhost:8082/realms/master/protocol/openid-connect/logout")
public interface KeycloakLogoutClient {
    @PostMapping
    void logout(@RequestParam("client_id") String clientId,
                @RequestParam("refresh_token") String refreshToken,
                @RequestParam("redirect_uri") String redirectUri);
}
