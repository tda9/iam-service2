package com.da.iam.service;

import com.da.iam.dto.request.LoginRequest;
import com.da.iam.dto.request.LogoutRequest;
import com.da.iam.dto.request.RegisterRequest;
import com.da.iam.dto.response.BaseTokenResponse;
import com.da.iam.entity.User;


public interface  BaseAuthenticationService {
    User register(RegisterRequest request);

    BaseTokenResponse login(LoginRequest loginRequest);

    BaseTokenResponse refreshToken(String refreshToken);

    void logout(LogoutRequest request);

    void resetPassword(String email, String newPassword, String token);

    void changePassword(String currentPassword, String newPassword, String confirmPassword, String email);
}
