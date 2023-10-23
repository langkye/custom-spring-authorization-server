package sample.config.provider.oauth2;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;

import java.util.Map;
import java.util.Set;

/**
 * @see OAuth2AuthorizationCodeRequestAuthenticationToken
 * @author langkye
 * @since 1.0.0.RELEASE
 */
public class CustomOAuth2AuthorizationCodeRequestAuthenticationToken extends OAuth2AuthorizationCodeRequestAuthenticationToken {
    /**
     * Constructs an {@code OAuth2AuthorizationCodeRequestAuthenticationToken} using the provided parameters.
     *
     * @param authorizationUri     the authorization URI
     * @param clientId             the client identifier
     * @param principal            the {@code Principal} (Resource Owner)
     * @param redirectUri          the redirect uri
     * @param state                the state
     * @param scopes               the requested scope(s)
     * @param additionalParameters the additional parameters
     * @since 0.4.0
     */
    public CustomOAuth2AuthorizationCodeRequestAuthenticationToken(String authorizationUri, String clientId, Authentication principal, String redirectUri, String state, Set<String> scopes, Map<String, Object> additionalParameters) {
        super(authorizationUri, clientId, principal, redirectUri, state, scopes, additionalParameters);
    }

    /**
     * Constructs an {@code OAuth2AuthorizationCodeRequestAuthenticationToken} using the provided parameters.
     *
     * @param authorizationUri  the authorization URI
     * @param clientId          the client identifier
     * @param principal         the {@code Principal} (Resource Owner)
     * @param authorizationCode the {@link OAuth2AuthorizationCode}
     * @param redirectUri       the redirect uri
     * @param state             the state
     * @param scopes            the authorized scope(s)
     * @since 0.4.0
     */
    public CustomOAuth2AuthorizationCodeRequestAuthenticationToken(String authorizationUri, String clientId, Authentication principal, OAuth2AuthorizationCode authorizationCode, String redirectUri, String state, Set<String> scopes) {
        super(authorizationUri, clientId, principal, authorizationCode, redirectUri, state, scopes);
    }
}
