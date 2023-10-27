package sample.config.provider;

import org.springframework.util.Assert;
import sample.config.provider.oauth2.CustomOAuth2AuthorizationCodeRequestAuthenticationToken;
import sample.config.provider.pwd.PasswordAuthenticationToken;
import sample.config.provider.sms.SmsAuthenticationToken;

import java.util.Objects;
import java.util.function.Function;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
public enum AuthType {
    unknown(0, "unknown", request -> {throw new UnsupportedOperationException("Not match from current type");}),
    password(10, "password", (request -> PasswordAuthenticationToken.unauthenticated(request, request))),
    sms(20, "password", (request -> SmsAuthenticationToken.unauthenticated(request, request))),
    oauth(30, "oauth", request -> {throw new UnsupportedOperationException("Not realized 4 oauth");}),
    social_bjtoon(40, "social_bjtoon", request -> {throw new UnsupportedOperationException("Not realized 4 social_bjtoon");}),
    social_yztoon(50, "social_yztoon", request -> {throw new UnsupportedOperationException("Not realized 4 social_yztoon");}),
    social_jban(60, "social_jban", request -> {throw new UnsupportedOperationException("Not realized 4 social_jban");}),
    social_wx(70, "social_wx", request -> {throw new UnsupportedOperationException("Not realized 4 social_wx");}),
    social_zfb(80, "social_zfb", request -> {throw new UnsupportedOperationException("Not realized 4 social_zfb");}),
    social_github(90, "social_github", request -> {throw new UnsupportedOperationException("Not realized 4 social_github");}),
    social_weibo(100, "social_weibo", request -> {throw new UnsupportedOperationException("Not realized 4 social_weibo");}),
    ;

    private final Number type;
    private final String typeName;
    private final Function<IAuthRequest, ITokenProvider> function;

    AuthType(Number type, String typeName, Function<IAuthRequest, ITokenProvider> function) {
        this.type = type;
        this.typeName = typeName;
        this.function = function;
    }

    public Number getType() {
        return type;
    }

    public String getTypeName() {
        return typeName;
    }

    public Function<IAuthRequest, ITokenProvider> getFunction() {
        return function;
    }
    
    public static AuthType of(Number type) {
        Assert.notNull(type, "loginType must be not null");
        for (AuthType value : AuthType.values()) {
            if (Objects.equals(value.type, type)) {
                return value;
            }
        }
        return unknown;
    }
}
