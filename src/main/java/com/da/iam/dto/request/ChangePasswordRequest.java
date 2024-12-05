package com.da.iam.dto.request;

import com.da.iam.utils.InputUtils;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;

public record ChangePasswordRequest(
        @Pattern(regexp = InputUtils.PASSWORD_PATTERN, message = "Invalid password format")
        String currentPassword,
        @Pattern(regexp = InputUtils.PASSWORD_PATTERN, message = "Invalid password format")
        String newPassword,
        @Pattern(regexp = InputUtils.PASSWORD_PATTERN, message = "Invalid password format")
        String confirmPassword,
        @NotEmpty(message = "Email cannot be empty")
        @Pattern(regexp = InputUtils.EMAIL_PATTERN, message = "Invalid email format")
        String email
) {
}
