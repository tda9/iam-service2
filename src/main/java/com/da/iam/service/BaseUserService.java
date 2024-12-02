package com.da.iam.service;

import com.da.iam.dto.request.CreateUserRequest;
import com.da.iam.dto.request.UpdateUserRequest;
import com.da.iam.dto.response.BasedResponse;

public interface BaseUserService {
    BasedResponse<?> create(CreateUserRequest request);
    BasedResponse<?> updateById(UpdateUserRequest request);
}
