package sample.config.provider.oauth2.jwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.*;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import sample.domain.oauth2.model.request.OAuth2Request;
import sample.domain.user.service.IUserService;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.*;
import java.util.stream.Collectors;

import static sample.config.provider.oauth2.AbstractOAuth2AuthenticationProvider.throwInvalidClient;
import static sample.config.provider.oauth2.AbstractOAuth2AuthenticationProvider.checkInvalidResponseType;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
//@Component
public class OAuth2JwtAuthenticationProvider implements AuthenticationProvider {
    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";
    private final Logger logger = LoggerFactory.getLogger(OAuth2JwtAuthenticationProvider.class);
    private static final OAuth2TokenType AUTHORIZATION_CODE_TOKEN_TYPE =
            new OAuth2TokenType(OAuth2ParameterNames.CODE);
    private static final OAuth2TokenType ID_TOKEN_TOKEN_TYPE =
            new OAuth2TokenType(OidcParameterNames.ID_TOKEN);

    @Resource private IUserService userDetailsService;
    @Resource private PasswordEncoder passwordEncoder;
    @Resource private RegisteredClientRepository registeredClientRepository;
    @Resource private OAuth2AuthorizationService authorizationService; //InMemoryOAuth2AuthorizationService
    /**
     * @see org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2TokenEndpointConfigurer#createDefaultAuthenticationProviders
     */
    @Resource private OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator; 
    @Resource private HttpServletRequest httpServletRequest;
    private MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

    private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        //OAuth2AuthorizationCodeAuthenticationToken authorizationCodeAuthentication =
        //        (OAuth2AuthorizationCodeAuthenticationToken) authentication;
        OAuth2JwtAuthenticationToken authorizationCodeAuthentication =
                (OAuth2JwtAuthenticationToken) authentication;

        // ----- Check parameter -----
        Assert.isInstanceOf(OAuth2JwtAuthenticationToken.class, authentication,
                () -> this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.onlySupports",
                        "Only OAuth2JwtAuthenticationToken is supported"));
        Object principal = authentication.getPrincipal();

        Assert.notNull(principal, "Principal is must be not null");
        Assert.isInstanceOf(OAuth2Request.class, principal,
                () -> this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.onlySupports",
                        "Only OAuth2Request is supported"));
        OAuth2Request request = (OAuth2Request) principal;
        String responseType = request.getResponseType();
        String clientId = request.getClientId();
        String scope = request.getScope();
        String redirectUri = request.getRedirectUri();
        String state = request.getState();

        Assert.notNull(responseType, "responseType is must be not null");
        Assert.notNull(clientId, "clientId is must be not null");
        Assert.notNull(scope, "scope is must be not null");
        Assert.notNull(redirectUri, "redirectUri is must be not null");

        checkInvalidResponseType(responseType);

        // load registered client
        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);

        if (Objects.isNull(registeredClient)) {
            throwInvalidClient(OAuth2ParameterNames.CLIENT_ID);
        }

        // match scope
        Set<String> scopes = registeredClient.getScopes();
        Set<String> requestScopes = Arrays.stream(scope.split(" ")).filter(it -> it != null  && !"".equals(it.trim())).collect(Collectors.toSet());
        if (!scopes.containsAll(requestScopes)) {
            throwInvalidClient(OAuth2ParameterNames.SCOPE);
        }

        // match redirectUir
        if (!registeredClient.getRedirectUris().contains(redirectUri.trim())) {
            throwInvalidClient(OAuth2ParameterNames.REDIRECT_URI);
        }

        // ----- Check consent -----

        // 是否需求用户授权
        ClientSettings clientSettings = registeredClient.getClientSettings();
        if (Objects.nonNull(clientSettings)) {
            boolean requireAuthorizationConsent = clientSettings.isRequireAuthorizationConsent();
            if (requireAuthorizationConsent) {
                //authenticationManager.authenticate(OAuth2ConsentAuthenticationToken.unauthenticated(request, request));
                // todo
            }
        }

        // ----- Check code -----
        OAuth2Authorization authorization = this.authorizationService.findByToken(
                request.getCode(), AUTHORIZATION_CODE_TOKEN_TYPE);
        if (authorization == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Retrieved authorization with authorization code");
        }

        OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode =
                authorization.getToken(OAuth2AuthorizationCode.class);

        if (!registeredClient.getClientId().equals(request.getClientId())) {
            if (!authorizationCode.isInvalidated()) {
                // Invalidate the authorization code given that a different client is attempting to use it
                authorization = OAuth2AuthenticationProviderUtils.invalidate(authorization, authorizationCode.getToken());
                this.authorizationService.save(authorization);
                if (this.logger.isWarnEnabled()) {
                    this.logger.warn(LogMessage.format("Invalidated authorization code used by registered client '%s'", registeredClient.getId()).toString());
                }
            }
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }

        // @formatter:off
        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(authorization.getAttribute(Principal.class.getName()))
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .authorization(authorization)
                .authorizedScopes(authorization.getAuthorizedScopes())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrant(authorizationCodeAuthentication);
        // @formatter:on

        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.from(authorization);

        // ----- Access token -----
        OAuth2TokenContext tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();
        OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);
        if (generatedAccessToken == null) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                    "The token generator failed to generate the access token.", ERROR_URI);
            throw new OAuth2AuthenticationException(error);
        }

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Generated access token");
        }

        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                generatedAccessToken.getTokenValue(), generatedAccessToken.getIssuedAt(),
                generatedAccessToken.getExpiresAt(), tokenContext.getAuthorizedScopes());
        if (generatedAccessToken instanceof ClaimAccessor) {
            authorizationBuilder.token(accessToken, (metadata) ->
                    metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, ((ClaimAccessor) generatedAccessToken).getClaims()));
        } else {
            authorizationBuilder.accessToken(accessToken);
        }

        // ----- Refresh token -----
        OAuth2RefreshToken refreshToken = null;
        if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN) &&
                // Do not issue refresh token to public client
                !request.getClientAuthenticationMethod().equals(ClientAuthenticationMethod.NONE)) {

            tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.REFRESH_TOKEN).build();
            OAuth2Token generatedRefreshToken = this.tokenGenerator.generate(tokenContext);
            if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
                OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                        "The token generator failed to generate the refresh token.", ERROR_URI);
                throw new OAuth2AuthenticationException(error);
            }

            if (this.logger.isTraceEnabled()) {
                this.logger.trace("Generated refresh token");
            }

            refreshToken = (OAuth2RefreshToken) generatedRefreshToken;
            authorizationBuilder.refreshToken(refreshToken);
        }

        // ----- ID token -----
        OidcIdToken idToken;
        if (request.getScope().contains(OidcScopes.OPENID)) {
            // @formatter:off
            tokenContext = tokenContextBuilder
                    .tokenType(ID_TOKEN_TOKEN_TYPE)
                    .authorization(authorizationBuilder.build())	// ID token customizer may need access to the access token and/or refresh token
                    .build();
            // @formatter:on
            OAuth2Token generatedIdToken = this.tokenGenerator.generate(tokenContext);
            if (!(generatedIdToken instanceof Jwt)) {
                OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                        "The token generator failed to generate the ID token.", ERROR_URI);
                throw new OAuth2AuthenticationException(error);
            }

            if (this.logger.isTraceEnabled()) {
                this.logger.trace("Generated id token");
            }

            idToken = new OidcIdToken(generatedIdToken.getTokenValue(), generatedIdToken.getIssuedAt(),
                    generatedIdToken.getExpiresAt(), ((Jwt) generatedIdToken).getClaims());
            authorizationBuilder.token(idToken, (metadata) ->
                    metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, idToken.getClaims()));
        } else {
            idToken = null;
        }

        authorization = authorizationBuilder.build();

        // Invalidate the authorization code as it can only be used once
        authorization = OAuth2AuthenticationProviderUtils.invalidate(authorization, authorizationCode.getToken());

        this.authorizationService.save(authorization);

        Map<String, Object> additionalParameters = Collections.emptyMap();
        if (idToken != null) {
            additionalParameters = new HashMap<>();
            additionalParameters.put(OidcParameterNames.ID_TOKEN, idToken.getTokenValue());
        }

        this.logger.debug("Authenticated oauth2");
        //         OAuth2AuthorizationCodeRequestAuthenticationToken
        //OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient, ClientAuthenticationMethod.CLIENT_SECRET_JWT, request.getClientSecret());
        Map<String, Object> oauth2ClientAdditionalParameters = OAuth2EndpointUtils.getParametersIfMatchesAuthorizationCodeGrantRequest(httpServletRequest,
                OAuth2ParameterNames.CLIENT_ASSERTION_TYPE,
                OAuth2ParameterNames.CLIENT_ASSERTION,
                OAuth2ParameterNames.CLIENT_ID);
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient.getClientId(), ClientAuthenticationMethod.CLIENT_SECRET_JWT, registeredClient.getClientSecret(), oauth2ClientAdditionalParameters);

        return new OAuth2AccessTokenAuthenticationToken(
                registeredClient, clientPrincipal, accessToken, refreshToken, additionalParameters);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return Objects.equals(OAuth2JwtAuthenticationToken.class, authentication);
    }


    /**
     * see org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthenticationProviderUtils
     */
    static class OAuth2AuthenticationProviderUtils {

        private OAuth2AuthenticationProviderUtils() {
        }

        static OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(Authentication authentication) {
            OAuth2ClientAuthenticationToken clientPrincipal = null;
            if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication.getPrincipal().getClass())) {
                clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
            }
            if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
                return clientPrincipal;
            }
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
        }

        static <T extends OAuth2Token> OAuth2Authorization invalidate(
                OAuth2Authorization authorization, T token) {

            // @formatter:off
            OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.from(authorization)
                    .token(token,
                            (metadata) ->
                                    metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true));

            if (OAuth2RefreshToken.class.isAssignableFrom(token.getClass())) {
                authorizationBuilder.token(
                        authorization.getAccessToken().getToken(),
                        (metadata) ->
                                metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true));

                OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode =
                        authorization.getToken(OAuth2AuthorizationCode.class);
                if (authorizationCode != null && !authorizationCode.isInvalidated()) {
                    authorizationBuilder.token(
                            authorizationCode.getToken(),
                            (metadata) ->
                                    metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true));
                }
            }
            // @formatter:on

            return authorizationBuilder.build();
        }
    }

    static class OAuth2EndpointUtils {
        static final String ACCESS_TOKEN_REQUEST_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

        private OAuth2EndpointUtils() {
        }

        static MultiValueMap<String, String> getParameters(HttpServletRequest request) {
            Map<String, String[]> parameterMap = request.getParameterMap();
            MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>(parameterMap.size());
            parameterMap.forEach((key, values) -> {
                if (values.length > 0) {
                    for (String value : values) {
                        parameters.add(key, value);
                    }
                }
            });
            return parameters;
        }

        static Map<String, Object> getParametersIfMatchesAuthorizationCodeGrantRequest(HttpServletRequest request, String... exclusions) {
            if (!matchesAuthorizationCodeGrantRequest(request)) {
                return Collections.emptyMap();
            }
            MultiValueMap<String, String> multiValueParameters = getParameters(request);
            for (String exclusion : exclusions) {
                multiValueParameters.remove(exclusion);
            }

            Map<String, Object> parameters = new HashMap<>();
            multiValueParameters.forEach((key, value) ->
                    parameters.put(key, (value.size() == 1) ? value.get(0) : value.toArray(new String[0])));

            return parameters;
        }

        static boolean matchesAuthorizationCodeGrantRequest(HttpServletRequest request) {
            return AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(
                    request.getParameter(OAuth2ParameterNames.GRANT_TYPE)) &&
                    request.getParameter(OAuth2ParameterNames.CODE) != null;
        }

        static boolean matchesPkceTokenRequest(HttpServletRequest request) {
            return matchesAuthorizationCodeGrantRequest(request) &&
                    request.getParameter(PkceParameterNames.CODE_VERIFIER) != null;
        }

        static void throwError(String errorCode, String parameterName, String errorUri) {
            OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, errorUri);
            throw new OAuth2AuthenticationException(error);
        }

    }
}
