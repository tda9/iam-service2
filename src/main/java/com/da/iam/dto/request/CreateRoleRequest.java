package com.da.iam.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.Builder;
import lombok.Data;

import java.util.Set;
import java.util.UUID;


public record CreateRoleRequest(
        @NotEmpty(message = "Role name can not be empty")
        String name,
        @NotEmpty(message = "Role permission can not be empty")
        Set<String> permissionsResourceName
){
}
