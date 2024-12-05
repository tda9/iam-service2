package com.da.iam.dto.request;

import jakarta.validation.constraints.NotEmpty;

public record RefreshTokenRequest(
        @NotEmpty(message = "Refresh token can not be empty")
        String refreshToken
) {
}
