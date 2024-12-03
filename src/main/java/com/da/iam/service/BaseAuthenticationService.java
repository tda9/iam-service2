package com.da.iam.service;

import com.da.iam.dto.request.LoginRequest;
import com.da.iam.dto.request.LogoutRequest;
import com.da.iam.dto.request.RegisterRequest;
import com.da.iam.dto.response.BaseTokenResponse;
import com.da.iam.dto.response.BasedResponse;
import com.da.iam.entity.User;
import com.da.iam.repo.RoleRepo;
import com.da.iam.repo.UserRepo;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;


public interface  BaseAuthenticationService {
    User register(RegisterRequest request);

    BaseTokenResponse login(LoginRequest loginRequest);

    <T> BasedResponse<?> getNewAccessToken(LogoutRequest request);

    BasedResponse<?> logout(LogoutRequest request);


}
