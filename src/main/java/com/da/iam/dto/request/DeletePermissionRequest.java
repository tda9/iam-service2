package com.da.iam.dto.request;

import jakarta.validation.constraints.NotEmpty;

import java.util.UUID;

public record DeletePermissionRequest(
        @NotEmpty(message = "Permission id can not be empty")
        String permissionId
) {

}
