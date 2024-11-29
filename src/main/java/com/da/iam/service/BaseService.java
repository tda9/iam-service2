package com.da.iam.service;

import com.da.iam.dto.request.LoginRequest;
import com.da.iam.dto.request.LogoutDto;
import com.da.iam.dto.request.RegisterRequest;
import com.da.iam.dto.response.BasedResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;


public interface BaseService {
    BasedResponse<?> register(RegisterRequest request);

    BasedResponse<?> login(LoginRequest loginRequest);

    <T> BasedResponse<?> getNewAccessToken(HttpServletRequest request);

    BasedResponse<?> logout(LogoutDto logoutDto);
    <T> BasedResponse<?> getNewAccessToken(T request);


    BasedResponse<?> getNewAccessTokenKeycloak(LogoutDto logoutDto);
}
