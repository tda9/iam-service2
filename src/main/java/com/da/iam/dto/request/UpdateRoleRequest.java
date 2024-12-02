package com.da.iam.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

import java.util.Set;
import java.util.UUID;

public record UpdateRoleRequest (
        @NotEmpty(message = "Role id can not be empty")
        String roleId,
        @NotEmpty(message = "Role name can not be empty")
        String name,
        @NotEmpty(message = "Role permission can not be empty")
        Set<String> permissionsResourceName,
        @NotNull(message = "Role deleted can not be null")
        Boolean deleted
){
}
