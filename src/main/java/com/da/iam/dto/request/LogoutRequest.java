package com.da.iam.dto.request;


import com.da.iam.utils.InputUtils;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

public record LogoutRequest(
        @NotEmpty
        String refreshToken,
        @Pattern(regexp = InputUtils.EMAIL_PATTERN, message = "Invalid email format")
        String email) {
}
