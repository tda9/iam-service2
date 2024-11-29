package com.da.iam.service;

import com.da.iam.dto.request.LogoutDto;
import org.keycloak.admin.client.Keycloak;

import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.List;

@Service
public class KeycloakService {
    @Value("${application.security.keycloak.logoutUrl}")
    private String LOGOUT_URL;

    public void logoutUser(LogoutDto logoutDto) {
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
    }
}
