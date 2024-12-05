package com.da.iam.service;

import com.da.iam.dto.response.DefaultTokenResponse;
import com.da.iam.entity.BlackListToken;
import com.da.iam.repo.BlackListTokenRepo;
import com.da.iam.repo.RoleRepo;
import com.da.iam.repo.UserRepo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@Slf4j
@RequiredArgsConstructor
public abstract class BaseService {
    protected final UserRepo userRepo;
    protected final RoleRepo roleRepo;
    protected final BlackListTokenRepo blackListTokenRepo;
    protected final JWTService jwtService;
    protected void checkEmailExisted(String email) {
        if (userRepo.existsByEmail(email)) {
            throw new IllegalArgumentException("Email existed");
        }
    }

    protected List<UUID> getRoles(Set<String> requestRoles) {
        return requestRoles.stream()
                .map(String::trim)
                .map(roleRepo::findRoleIdByName)
                .peek(role -> {
                    if (role.isEmpty() || roleRepo.isRoleDeleted(role.get()).orElseThrow()) {
                        throw new IllegalArgumentException("Role not found or deleted");
                    }
                })
                .map(Optional::get)
                .toList();
    }
    @Value("${application.security.jwt.expiration}")
    private long jwtExpiration;
    @Value("${application.security.jwt.refresh-token.expiration}")
    private long refreshExpiration;
    protected DefaultTokenResponse generateDefaultToken(String email, UUID userId) {
        var jwtToken = jwtService.generateToken(email);
        var jwtRefreshToken = jwtService.generateRefreshToken(email);
        DefaultTokenResponse tokenResponse = new DefaultTokenResponse(jwtToken, jwtRefreshToken, "Bearer", jwtExpiration, refreshExpiration);
        blackListTokenRepo.save(BlackListToken.builder()
                .token(jwtToken)
                .expirationDate(LocalDateTime.now().plusMinutes(jwtExpiration))
                .userId(userId)
                .build());
        return tokenResponse;
    }
}
