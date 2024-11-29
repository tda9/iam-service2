package com.da.iam.dto.request;

import lombok.Builder;
import lombok.Data;

import java.util.UUID;

@Data
@Builder
public class PermissionDTO implements BasedRequest {
    private UUID permissionId;
    private String resourceCode;
    private String resourceName;
    private boolean deleted;
    private String scope;
}
