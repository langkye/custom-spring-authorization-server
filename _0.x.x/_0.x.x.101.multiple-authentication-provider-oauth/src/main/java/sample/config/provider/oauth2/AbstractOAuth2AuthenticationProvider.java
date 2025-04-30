package sample.config.provider.oauth2;

import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;

import java.util.Arrays;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
public abstract class AbstractOAuth2AuthenticationProvider {
    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-3.2.1";

    /**
     * see {@link OAuth2AuthorizationResponseType}
     */
    public static void checkInvalidResponseType(String responseType) {
        if (!Arrays.asList(OAuth2AuthorizationResponseType.CODE.getValue(), OAuth2AuthorizationResponseType.TOKEN.getValue()).contains(responseType)) {
            throwInvalidClient(OAuth2ParameterNames.RESPONSE_TYPE);
        }
    }

    public static void throwInvalidClient(String parameterName) {
        throwInvalidClient(parameterName, null);
    }

    protected static void throwInvalidClient(String parameterName, Throwable cause) {
        OAuth2Error error = new OAuth2Error(
                OAuth2ErrorCodes.INVALID_CLIENT,
                "Client authentication failed: " + parameterName,
                ERROR_URI
        );
        throw new OAuth2AuthenticationException(error, error.toString(), cause);
    }
    
}
