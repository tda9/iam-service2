package com.da.iam.controller;

import com.da.iam.controller.factory.AuthenticationServiceFactory;
import com.da.iam.dto.request.LoginRequest;
import com.da.iam.dto.request.LogoutRequest;
import com.da.iam.dto.request.RegisterRequest;
import com.da.iam.dto.response.BasedResponse;
import com.da.iam.exception.ErrorResponseException;
import com.da.iam.service.impl.KeycloakAuthenticationService;
import com.da.iam.service.PasswordService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RequiredArgsConstructor
@RestController
public class AuthenticationController {
    private final PasswordService passwordService;
    private final AuthenticationServiceFactory authenticationServiceFactory;

    @GetMapping("/confirmation-registration")
    public BasedResponse<?> confirmRegister(@RequestParam String email, @RequestParam String token){
        try {
            passwordService.confirmRegisterEmail(email, token);
            return BasedResponse.success("Confirm successful",email);
        } catch (Exception e) {
            throw new ErrorResponseException(e.getMessage());
        }
    }

    @PostMapping("/register")
    public BasedResponse<?> register(@RequestBody @Valid RegisterRequest request) {
        return BasedResponse.success("Register successful",
                        authenticationServiceFactory.getService().register(request));
    }

    @PostMapping("/login")
    public BasedResponse<?> login(@RequestBody @Valid LoginRequest request) {
        return BasedResponse.success("Login successful",
                authenticationServiceFactory.getService().login(request));
    }
    @PostMapping("/api/logout")
    public String logout(@RequestBody LogoutRequest request) {
        authenticationServiceFactory.getService().logout(request);
        return "Logout request has been sent.";
    }

    @PostMapping("/refresh-token")
    public BasedResponse<?> refreshToken(@RequestParam String request) {
        return BasedResponse.success("Refresh token successful",
                authenticationServiceFactory.getService().refreshToken(request));
    }
    @PostMapping("/change-password")
    public BasedResponse<?> changePassword(
            @RequestParam String currentPassword, @RequestParam String newPassword,
            @RequestParam String confirmPassword, @RequestParam String email) {
        authenticationServiceFactory.getService().changePassword(currentPassword, newPassword, confirmPassword, email);
        return BasedResponse.builder()
                .httpStatusCode(200)
                .requestStatus(true)
                .message("Change password successful")
                .data(email)
                .build();
    }

    @PostMapping("/forgot-password")
    public BasedResponse<?> forgotPassword(@RequestParam String email) {
        try {
            passwordService.forgotPassword(email);
            return BasedResponse.success("If your email existed, you will receive a link", email);
        } catch (Exception e) {
            throw new ErrorResponseException("Error forgot password");
        }
    }

    @GetMapping("/reset-password")
    public BasedResponse<?> resetPassword(@RequestParam String email, @RequestParam String newPassword, @RequestParam String token) {
        authenticationServiceFactory.getService().resetPassword(email, newPassword, token);
        return BasedResponse.success("Reset password successful",email);
    }

    @PreAuthorize("hasPermission('HOMEPAGE','VIEW')")
    @GetMapping("/hello")
    public String test() {
        return "Hello HOMEPAGE";
    }

    @PreAuthorize("hasPermission('DASHBOARD','VIEW')")
    @GetMapping("/admin")
    public String test1() {
        return "Hello DASHBOARD ";
    }
    @GetMapping("/custom-login")
    public BasedResponse<?> redirectToKeycloakLogin() {
        return BasedResponse.builder()
                .requestStatus(true)
                .message("Please redirects to the Keycloak login page")
                .data("http://localhost:8082")
                .httpStatusCode(301)
                .build();
    }
}
