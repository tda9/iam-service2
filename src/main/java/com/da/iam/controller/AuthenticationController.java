package com.da.iam.controller;

import com.da.iam.dto.request.LoginRequest;
import com.da.iam.dto.request.LogoutDto;
import com.da.iam.dto.request.RegisterRequest;
import com.da.iam.dto.response.BasedResponse;
import com.da.iam.exception.ErrorResponseException;
import com.da.iam.service.AuthenticationService;
import com.da.iam.service.KeycloakService;
import com.da.iam.service.PasswordService;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.view.RedirectView;

import java.util.Map;

@AllArgsConstructor
@RestController
public class AuthenticationController {
    private final PasswordService passwordService;
    private final AuthenticationService authenticationService;
    private final KeycloakService keycloakService;
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
        return authenticationService.register(request);
    }

    @PostMapping("/login")
    public BasedResponse<?> login(@RequestBody LoginRequest request) {
            return authenticationService.authenticate(request);
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
//
//    @PreAuthorize("hasAnyRole('USER','ADMIN')")
//    @PostMapping("/change-password")
//    public BasedResponse<?> changePassword(
//            @RequestParam String currentPassword, @RequestParam String newPassword,
//            @RequestParam String confirmPassword, @RequestParam String email) {
//        passwordService.changePassword(currentPassword, newPassword, confirmPassword, email);
//        return BasedResponse.builder()
//                .httpStatusCode(200)
//                .requestStatus(true)
//                .message("Change password successful")
//                .data(email)
//                .build();
//    }
//
//    @PostMapping("/forgot-password")
//    public BasedResponse<?> forgotPassword(@RequestParam String email) {
//        try {
//            passwordService.forgotPassword(email);
//            return BasedResponse.builder()
//                    .data(email)
//                    .httpStatusCode(200)
//                    .requestStatus(true)
//                    .message("Sending Mail Reset Password Successful")
//                    .build();
//        } catch (Exception e) {
//            throw new ErrorResponseException("Error forgot password");
//        }
//    }
//
//    @GetMapping("/reset-password")
//    public BasedResponse<?> resetPassword(@RequestParam String email, @RequestParam String newPassword, @RequestParam String token) {
//        passwordService.resetPassword(email, newPassword, token);
//        return BasedResponse.builder()
//                .httpStatusCode(200)
//                .requestStatus(true)
//                .data(email)
//                .message("Reset password successful")
//                .build();
//    }
//
//    @PostMapping("/api/logout")//de /logout khong se trung default url, va khong chay dc
//    public BasedResponse<?> logout(@RequestParam String email) {
//        authenticationService.logout(email);
//        return BasedResponse.builder()
//                .httpStatusCode(200)
//                .requestStatus(true)
//                .message("Logged out")
//                .data(email)
//                .build();
//    }

    @PreAuthorize("hasAuthority('USER.VIEW')")
    @GetMapping("/hello")
    //@PreAuthorize("hasAnyRole('USER','ADMIN')")
    public String test() {
        return "Hello World";
    }

    @PreAuthorize("hasAuthority('USER_MANAGER.VIEW')")
    @GetMapping("/admin")
    //@PreAuthorize("hasAnyRole('ADMIN')")
    public String test1() {
        return "Hello World USER_MANAGER";
    }

    @PostMapping("/api/logout")
    public String logout(@RequestBody LogoutDto logoutDto) {
        keycloakService.logoutUser(logoutDto);
        return "Logout request has been sent.";
    }
}
