package com.da.iam.dto.request;


public record LogoutRequest(String refreshToken, String email) {
}
