package com.da.iam.dto.request;

import lombok.Data;
import lombok.EqualsAndHashCode;


public record LogoutDto(String refreshToken) {
}
