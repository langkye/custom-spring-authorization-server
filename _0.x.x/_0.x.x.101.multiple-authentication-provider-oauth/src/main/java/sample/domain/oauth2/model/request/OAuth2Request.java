package sample.domain.oauth2.model.request;

import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import sample.config.provider.IAuthRequest;
import sample.config.provider.AuthType;

/**
 * see {@link OAuth2ParameterNames}
 * @author langkye
 * @since 1.0.0.RELEASE
 */
public class OAuth2Request implements IAuthRequest {

    /**
     * {@code grant_type} - used in Access Token Request.
     */
    private String grantType;

    /**
     * {@code response_type} - used in Authorization Request.
     */
    private String responseType;

    /**
     * {@code client_id} - used in Authorization Request and Access Token Request.
     */
    private String clientId;

    /**
     * {@code client_secret} - used in Access Token Request.
     */
    private String clientSecret;

    /**
     * {@code client_assertion_type} - used in Access Token Request.
     * @since 5.5
     */
    private String clientAssertionType;

    /**
     * {@code client_assertion} - used in Access Token Request.
     * @since 5.5
     */
    private String clientAssertion;

    /**
     * {@code assertion} - used in Access Token Request.
     * @since 5.5
     */
    private String assertion;

    /**
     * {@code redirect_uri} - used in Authorization Request and Access Token Request.
     */
    private String redirectUri;

    /**
     * {@code scope} - used in Authorization Request, Authorization Response, Access Token
     * Request and Access Token Response.
     */
    private String scope;

    /**
     * {@code state} - used in Authorization Request and Authorization Response.
     */
    private String state;

    /**
     * {@code code} - used in Authorization Response and Access Token Request.
     */
    private String code;

    /**
     * {@code access_token} - used in Authorization Response and Access Token Response.
     */
    private String accessToken;

    /**
     * {@code token_type} - used in Authorization Response and Access Token Response.
     */
    private String tokenType;

    /**
     * {@code expires_in} - used in Authorization Response and Access Token Response.
     */
    private String expiresIn;

    /**
     * {@code refresh_token} - used in Access Token Request and Access Token Response.
     */
    private String refreshToken;

    /**
     * {@code username} - used in Access Token Request.
     */
    private String username;

    /**
     * {@code password} - used in Access Token Request.
     */
    private String password;

    /**
     * {@code error} - used in Authorization Response and Access Token Response.
     */
    private String error;

    /**
     * {@code error_description} - used in Authorization Response and Access Token
     * Response.
     */
    private String errorDescription;

    /**
     * {@code error_uri} - used in Authorization Response and Access Token Response.
     */
    private String errorUri;

    /**
     * Non-standard parameter (used internally).
     */
    private String registrationId;

    /**
     * {@code token} - used in Token Revocation Request.
     * @since 5.5
     */
    private String token;

    /**
     * {@code token_type_hint} - used in Token Revocation Request.
     * @since 5.5
     */
    private String tokenTypeHint;
    private ClientAuthenticationMethod clientAuthenticationMethod = ClientAuthenticationMethod.CLIENT_SECRET_JWT;

    @Override
    public Number getAuthType() {
        return AuthType.oauth.getType();
    }

    public String getGrantType() {
        return grantType;
    }

    public void setGrantType(String grantType) {
        this.grantType = grantType;
    }

    public String getResponseType() {
        return responseType;
    }

    public void setResponseType(String responseType) {
        this.responseType = responseType;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getClientAssertionType() {
        return clientAssertionType;
    }

    public void setClientAssertionType(String clientAssertionType) {
        this.clientAssertionType = clientAssertionType;
    }

    public String getClientAssertion() {
        return clientAssertion;
    }

    public void setClientAssertion(String clientAssertion) {
        this.clientAssertion = clientAssertion;
    }

    public String getAssertion() {
        return assertion;
    }

    public void setAssertion(String assertion) {
        this.assertion = assertion;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    public String getExpiresIn() {
        return expiresIn;
    }

    public void setExpiresIn(String expiresIn) {
        this.expiresIn = expiresIn;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    public String getErrorDescription() {
        return errorDescription;
    }

    public void setErrorDescription(String errorDescription) {
        this.errorDescription = errorDescription;
    }

    public String getErrorUri() {
        return errorUri;
    }

    public void setErrorUri(String errorUri) {
        this.errorUri = errorUri;
    }

    public String getRegistrationId() {
        return registrationId;
    }

    public void setRegistrationId(String registrationId) {
        this.registrationId = registrationId;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getTokenTypeHint() {
        return tokenTypeHint;
    }

    public void setTokenTypeHint(String tokenTypeHint) {
        this.tokenTypeHint = tokenTypeHint;
    }

    public ClientAuthenticationMethod getClientAuthenticationMethod() {
        return clientAuthenticationMethod;
    }

    public void setClientAuthenticationMethod(ClientAuthenticationMethod clientAuthenticationMethod) {
        this.clientAuthenticationMethod = clientAuthenticationMethod;
    }
}
