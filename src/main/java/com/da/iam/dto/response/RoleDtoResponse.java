package com.da.iam.dto.response;

import com.da.iam.entity.Permission;
import com.da.iam.entity.RolePermissions;
import lombok.Builder;
import lombok.Data;

import java.util.Set;
import java.util.UUID;

@Builder
@Data
public class RoleDtoResponse {
    private String name;
    private boolean deleted;
    private Set<RolePermissionDtoResponse> rolePermissionDtoResponse;
}
