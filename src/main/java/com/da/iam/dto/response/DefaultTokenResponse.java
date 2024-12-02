package com.da.iam.dto.response;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class DefaultTokenResponse {
    private String accessToken;
    private String refreshToken;
    private String tokenType;
//    private int expiresIn;
//    private int refreshExpiresIn;
//    private String idToken;
    public DefaultTokenResponse(String accessToken, String refreshToken, String tokenType) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.tokenType = tokenType;
        //this.expiresIn = expiresIn;
        //this.refreshExpiresIn = refreshExpiresIn;
        //this.idToken = idToken;
    }
    public DefaultTokenResponse(String accessToken, String refreshToken, String tokenType, int expiresIn, int refreshExpiresIn, String idToken, String scope) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.tokenType = tokenType;
        //this.expiresIn = expiresIn;
        //this.refreshExpiresIn = refreshExpiresIn;
        //this.idToken = idToken;
    }
}
