package com.da.iam.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import lombok.Builder;
import lombok.Data;

import java.util.Set;
import java.util.UUID;


public record CreateRoleRequest(
        @NotEmpty(message = "Role name can not be empty")
        @Pattern(regexp = "^[a-zA-Z0-9_-]{3,}$", message = "Role name must contain letters or digits with minimum 3 character")
        String name,
        @NotEmpty(message = "Resource name can not be empty")
        Set<String> permissionsResourceName
){
}
