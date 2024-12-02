package com.da.iam.controller;

import com.da.iam.dto.request.LoginRequest;
import com.da.iam.dto.request.LogoutRequest;
import com.da.iam.dto.request.RegisterRequest;
import com.da.iam.dto.response.BasedResponse;
import com.da.iam.exception.ErrorResponseException;
import com.da.iam.service.KeycloakAuthenticationService;
import com.da.iam.service.PasswordService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RequiredArgsConstructor
@RestController
public class AuthenticationController {
    private final PasswordService passwordService;
    private final AuthenticationServiceFactory authenticationServiceFactory;
    private final KeycloakAuthenticationService keycloakAuthenticationService;
//    @GetMapping("/confirmation-registration")
//    public BasedResponse<?> confirmRegister(@RequestParam String email, @RequestParam String token){
//        try {
//            authenticationService.confirmEmail(email, token);
//            return BasedResponse.builder()
//                    .httpStatusCode(200)
//                    .requestStatus(true)
//                    .message("Confirm register successful")
//                    .data(email)
//                    .build();
//        } catch (Exception e) {
//            throw new ErrorResponseException(e.getMessage());
//        }
//    }

    @PostMapping("/register")
    public BasedResponse<?> register(@RequestBody RegisterRequest request) {
        return authenticationServiceFactory.getService().register(request);
    }

    @PostMapping("/login")
    public BasedResponse<?> login(@RequestBody LoginRequest request) {
            return authenticationServiceFactory.getService().login(request);
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

//    @PreAuthorize("hasAnyRole('USER','ADMIN')")
    @PostMapping("/change-password")
    public BasedResponse<?> changePassword(
            @RequestParam String currentPassword, @RequestParam String newPassword,
            @RequestParam String confirmPassword, @RequestParam String email) {
        keycloakAuthenticationService.changePassword(currentPassword, newPassword, confirmPassword, email);
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
            keycloakAuthenticationService.forgotPassword(email);
            return BasedResponse.builder()
                    .data(email)
                    .httpStatusCode(200)
                    .requestStatus(true)
                    .message("Sending Mail Reset Password Successful")
                    .build();
        } catch (Exception e) {
            throw new ErrorResponseException("Error forgot password");
        }
    }

    @GetMapping("/reset-password")
    public BasedResponse<?> resetPassword(@RequestParam String email, @RequestParam String newPassword, @RequestParam String token) {
        keycloakAuthenticationService.resetPassword(email, newPassword, token);
        return BasedResponse.builder()
                .httpStatusCode(200)
                .requestStatus(true)
                .data(email)
                .message("Reset password successful")
                .build();
    }


    @PreAuthorize("hasPermission(null,'USER.VIEW')")
    @GetMapping("/hello")
    //@PreAuthorize("hasAnyRole('USER','ADMIN')")
    public String test() {
        return "Hello World";
    }

    @PreAuthorize("hasPermission(null,'USER.READ')")
    @GetMapping("/admin")
    //@PreAuthorize("hasAnyRole('ADMIN')")
    public String test1() {
        return "Hello World USER_MANAGER";
    }

    @PostMapping("/api/logout")
    public String logout(@RequestBody LogoutRequest request) {
        authenticationServiceFactory.getService().logout(request);
        return "Logout request has been sent.";
    }

    @PostMapping("/get-new-access-token")
    public BasedResponse<?> getNewAccessToken(@RequestBody LogoutRequest request) {
        return authenticationServiceFactory.getService().getNewAccessTokenKeycloak(request);
    }

    @PostMapping("/refresh-token")
    public BasedResponse<?> refreshToken(@RequestParam String refreshToken) {
        return authenticationServiceFactory.getService().getNewAccessToken(refreshToken);
    }
}
