package com.da.iam.dto.request;

import lombok.Builder;


@Builder
public record LoginRequest(String email, String password) {
}
