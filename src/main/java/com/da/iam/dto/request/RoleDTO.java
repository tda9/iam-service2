package com.da.iam.dto.request;

import lombok.Builder;
import lombok.Data;

import java.util.Set;
import java.util.UUID;

@Data
@Builder
public class RoleDTO implements BasedRequest{
    private UUID roleId;
    private String name;
    private boolean deleted;
    private Set<String> permissions;
}
