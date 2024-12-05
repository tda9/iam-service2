package com.da.iam.dto.response;

import com.da.iam.entity.Role;
import com.da.iam.entity.User;
import lombok.Builder;

import java.util.List;
import java.util.Set;

@Builder
public record UserDtoResponse(
        User user,
        Set<Role> roles
) {

}
