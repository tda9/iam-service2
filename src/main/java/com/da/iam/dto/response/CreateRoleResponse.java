package com.da.iam.dto.response;

import lombok.Builder;
import lombok.Data;

import java.util.Set;

@Builder
@Data
public class CreateRoleResponse {
    private String name;
    private boolean deleted;
    private Set<RolePermissionResponse> rolePermissionDtoResponse;
}
