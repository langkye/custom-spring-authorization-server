package sample.property;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

import java.util.HashSet;
import java.util.Set;

/**
 * @author langkye
 */
@Validated
@Configuration
@ConfigurationProperties(prefix = "authorization")
public class AuthorizationProperties {

    private Jwt jwt = new Jwt();
    private Server server = new Server();
    private Security security = new Security();

    public Jwt getJwt() {
        return jwt;
    }

    public void setJwt(Jwt jwt) {
        this.jwt = jwt;
    }

    public Server getServer() {
        return server;
    }

    public void setServer(Server server) {
        this.server = server;
    }

    public Security getSecurity() {
        return security;
    }

    public void setSecurity(Security security) {
        this.security = security;
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
    
    public static class Server {
        private String issuer = "https://www.lnkdoc.cn";
        private String authorizationEndpoint = "/oauth2/authorize";
        private String oidcUserInfoEndpoint = "/api/userinfo";
        private String tokenEndpoint = "/oauth2/token";
        private String jwkSetEndpoint = "/.well-known/jwks.json";
        private String openidConfiguration = "/.well-known/openid-configuration";

        public String getIssuer() {
            return issuer;
        }

        public void setIssuer(String issuer) {
            this.issuer = issuer;
        }

        public String getAuthorizationEndpoint() {
            return authorizationEndpoint;
        }

        public void setAuthorizationEndpoint(String authorizationEndpoint) {
            this.authorizationEndpoint = authorizationEndpoint;
        }

        public String getOidcUserInfoEndpoint() {
            return oidcUserInfoEndpoint;
        }

        public void setOidcUserInfoEndpoint(String oidcUserInfoEndpoint) {
            this.oidcUserInfoEndpoint = oidcUserInfoEndpoint;
        }

        public String getTokenEndpoint() {
            return tokenEndpoint;
        }

        public void setTokenEndpoint(String tokenEndpoint) {
            this.tokenEndpoint = tokenEndpoint;
        }

        public String getJwkSetEndpoint() {
            return jwkSetEndpoint;
        }

        public void setJwkSetEndpoint(String jwkSetEndpoint) {
            this.jwkSetEndpoint = jwkSetEndpoint;
        }

        public String getOpenidConfiguration() {
            return openidConfiguration;
        }

        public void setOpenidConfiguration(String openidConfiguration) {
            this.openidConfiguration = openidConfiguration;
        }
    }
    
    public static class Security {
        private Set<String> permitUri = new HashSet<>();

        public Set<String> getPermitUri() {
            return permitUri;
        }

        public void setPermitUri(Set<String> permitUri) {
            this.permitUri = permitUri;
        }
    }
}
