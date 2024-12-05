package com.da.iam.dto.request;

import com.da.iam.utils.InputUtils;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.Builder;


@Builder
public record LoginRequest(
        @NotEmpty
        @Pattern(regexp = InputUtils.EMAIL_PATTERN, message = "Invalid email format")
        String email,
        @NotEmpty String password) {
}
