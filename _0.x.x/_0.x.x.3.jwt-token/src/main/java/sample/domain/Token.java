package sample.domain;

import java.io.Serializable;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
public class Token implements Serializable {
    private static final long serialVersionUID = 1L;
    private String accessToken;
    private Long accessTokenExpiredTime;
    private String refreshToken;
    private Long refreshTokenExpiredTime;

    private Token() {
    }

    private Token(String accessToken, Long accessTokenExpiredTime, String refreshToken, Long refreshTokenExpiredTime) {
        this.accessToken = accessToken;
        this.accessTokenExpiredTime = accessTokenExpiredTime;
        this.refreshToken = refreshToken;
        this.refreshTokenExpiredTime = refreshTokenExpiredTime;
    }

    public static Token newInstances() {
        return new Token();
    }

    public Token withRefreshTokenExpiredTime(Long refreshTokenExpiredTime) {
        this.refreshTokenExpiredTime = refreshTokenExpiredTime;
        return this;
    }

    public Token withRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
        return this;
    }

    public Token withAccessTokenExpiredTime(Long accessTokenExpiredTime) {
        this.accessTokenExpiredTime = accessTokenExpiredTime;
        return this;
    }

    public Token withAccessToken(String accessToken) {
        this.accessToken = accessToken;
        return this;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public Long getAccessTokenExpiredTime() {
        return accessTokenExpiredTime;
    }

    public void setAccessTokenExpiredTime(Long accessTokenExpiredTime) {
        this.accessTokenExpiredTime = accessTokenExpiredTime;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public Long getRefreshTokenExpiredTime() {
        return refreshTokenExpiredTime;
    }

    public void setRefreshTokenExpiredTime(Long refreshTokenExpiredTime) {
        this.refreshTokenExpiredTime = refreshTokenExpiredTime;
    }
    
}
