package com.da.iam.service;

import com.da.iam.dto.request.LoginRequest;
import com.da.iam.dto.request.LogoutRequest;
import com.da.iam.dto.request.RegisterRequest;
import com.da.iam.dto.response.BasedResponse;
import jakarta.servlet.http.HttpServletRequest;


public interface BaseAuthenticationService {
    BasedResponse<?> register(RegisterRequest request);

    BasedResponse<?> login(LoginRequest loginRequest);

    <T> BasedResponse<?> getNewAccessToken(String refreshToken);

    BasedResponse<?> logout(LogoutRequest request);
    <T> BasedResponse<?> getNewAccessToken(T request);


    BasedResponse<?> getNewAccessTokenKeycloak(LogoutRequest request);
}
