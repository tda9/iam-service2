package com.da.iam.dto.request;

import com.da.iam.annotation.ValidScope;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record CreatePermissionRequest(
        @Pattern(regexp = "^[a-zA-Z0-9_-]{3,}$", message = "Resource code must be alphanumeric with minimum 3 letters")
        @NotBlank(message = "Resource code can not be blank")
        String resourceCode,
        @Pattern(regexp = "^[a-zA-Z0-9_-]{3,}$", message = "Resource name must be alphanumeric with minimum 3 letters")
        @NotBlank(message = "Resource name can not be blank")
        String resourceName,
        @ValidScope
        String scope) {
}
