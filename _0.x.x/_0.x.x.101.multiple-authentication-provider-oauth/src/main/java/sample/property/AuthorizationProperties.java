package sample.property;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

/**
 * @author langkye
 */
@Validated
@Configuration
@ConfigurationProperties(prefix = "authorization")
public class AuthorizationProperties {

    private Jwt jwt = new Jwt();

    public Jwt getJwt() {
        return jwt;
    }

    public void setJwt(Jwt jwt) {
        this.jwt = jwt;
    }

    public static class Jwt {

        private String header = "Authorization"; // HTTP 报头的认证字段的 key

        private String prefix = "Bearer "; // HTTP 报头的认证字段的值的前缀

        //@Min(5000L)
        private long accessTokenExpireTime = 60 * 1000L; // Access Token 过期时间

        //@Min(3600000L)
        private long refreshTokenExpireTime = 30 * 24 * 3600 * 1000L; // Refresh Token 过期时间

        private String key;

        private String refreshKey;

        public String getHeader() {
            return header;
        }

        public void setHeader(String header) {
            this.header = header;
        }

        public String getPrefix() {
            return prefix;
        }

        public void setPrefix(String prefix) {
            this.prefix = prefix;
        }

        public long getAccessTokenExpireTime() {
            return accessTokenExpireTime;
        }

        public void setAccessTokenExpireTime(long accessTokenExpireTime) {
            this.accessTokenExpireTime = accessTokenExpireTime;
        }

        public long getRefreshTokenExpireTime() {
            return refreshTokenExpireTime;
        }

        public void setRefreshTokenExpireTime(long refreshTokenExpireTime) {
            this.refreshTokenExpireTime = refreshTokenExpireTime;
        }

        public String getKey() {
            return key;
        }

        public void setKey(String key) {
            this.key = key;
        }

        public String getRefreshKey() {
            return refreshKey;
        }

        public void setRefreshKey(String refreshKey) {
            this.refreshKey = refreshKey;
        }
    }
}
