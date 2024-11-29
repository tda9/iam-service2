package com.da.iam.dto.response;

import jakarta.persistence.Column;
import lombok.Builder;
import lombok.Data;

import java.util.UUID;
@Builder
@Data
public class RolePermissionDtoResponse {
    private UUID roleId;
    private UUID permissionId;
    private String resourceCode;
    private String resourceName;
    private String scope;
}
