package com.da.iam.dto.request;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

import java.util.UUID;

public record UpdatePermissionRequest(
        @NotEmpty(message = "Permission id can not be empty")
        String permissionId,
        @NotNull(message = "Resource name can not be null")
        String resourceName,
        @NotNull(message = "Scope can not be null")
        String scope,
        @NotNull(message = "Resource code can not be null")
        String resourceCode,
        @NotNull(message = "Deleted can not be null")
        Boolean deleted
) {
}
