package com.da.iam.dto.request;

import com.da.iam.annotation.ValidScope;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record CreatePermissionRequest(
        @NotBlank(message = "Resource code can not be blank")
        @Pattern(regexp = "^[a-zA-Z0-9_-]{3,}$", message = "Resource code must contain letters or digits with minimum 3 character")
        String resourceCode,
        @NotBlank(message = "Resource name can not be blank")
        @Pattern(regexp = "^[a-zA-Z0-9_-]{3,}$", message = "Resource name must contain letters or digits with minimum 3 character")
        String resourceName,
        @ValidScope
        String scope) {
}
