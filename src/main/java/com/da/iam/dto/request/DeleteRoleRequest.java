package com.da.iam.dto.request;

import jakarta.validation.constraints.NotEmpty;

import java.util.UUID;

public record DeleteRoleRequest(
        @NotEmpty(message = "ROLE_ID_REQUIRED")
        String roleId) {
}
