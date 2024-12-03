package com.da.iam.service;

import com.da.iam.dto.request.CreateUserRequest;
import com.da.iam.dto.request.UpdateUserRequest;
import com.da.iam.dto.response.BasedResponse;
import com.da.iam.entity.User;

public interface BaseUserService {
    User create(CreateUserRequest request);
    BasedResponse<?> updateById(UpdateUserRequest request);
}
