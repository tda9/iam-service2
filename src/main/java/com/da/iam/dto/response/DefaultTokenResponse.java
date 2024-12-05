package com.da.iam.dto.response;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
@Builder
public class DefaultTokenResponse implements BaseTokenResponse{
    private String accessToken;
    private String refreshToken;
    private String tokenType;
    private long expiresIn;
    private long refreshExpiresIn;
//    private String idToken;
//    public DefaultTokenResponse(String accessToken, String refreshToken, String tokenType) {
//        this.accessToken = accessToken;
//        this.refreshToken = refreshToken;
//        this.tokenType = tokenType;
//        this.expiresIn = expiresIn;
//        this.refreshExpiresIn = refreshExpiresIn;
//        //this.idToken = idToken;
//    }
    public DefaultTokenResponse(String accessToken, String refreshToken, String tokenType, long expiresIn, long refreshExpiresIn) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.tokenType = tokenType;
        this.expiresIn = expiresIn;
        this.refreshExpiresIn = refreshExpiresIn;
        //this.idToken = idToken;
    }
}
