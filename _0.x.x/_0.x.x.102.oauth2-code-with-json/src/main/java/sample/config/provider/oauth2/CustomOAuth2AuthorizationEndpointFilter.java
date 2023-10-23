package sample.config.provider.oauth2;

import org.springframework.core.log.LogMessage;
import org.springframework.http.HttpMethod;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationConsentAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.web.OAuth2AuthorizationEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.authentication.DelegatingAuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.util.matcher.*;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import sample.config.provider.consent.CustomOAuth2AuthorizationConsentAuthenticationToken;
import sample.config.provider.consent.converter.CustomOAuth2AuthorizationConsentAuthenticationConverter;
import sample.config.provider.oauth2.converter.CustomOAuth2AuthorizationCodeRequestAuthenticationConverter;

import javax.annotation.Resource;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * @see OAuth2AuthorizationEndpointFilter
 * @author langkye
 * @since 1.0.0.RELEASE
 */
//@Component
public class CustomOAuth2AuthorizationEndpointFilter extends OncePerRequestFilter {
    private static final String DEFAULT_AUTHORIZATION_ENDPOINT_URI = "/oauth2/authorize";

    /**
     * @see org.springframework.security.authentication.ProviderManager
     */
    @Resource
    private final AuthenticationManager authenticationManager;
    private final RequestMatcher authorizationEndpointMatcher;
    private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();
    private AuthenticationConverter authenticationConverter;
    private AuthenticationSuccessHandler authenticationSuccessHandler;
    private AuthenticationFailureHandler authenticationFailureHandler;

    /**
     * Constructs an {@code OAuth2AuthorizationEndpointFilter} using the provided parameters.
     *
     * @param authenticationManager the authentication manager
     */
    public CustomOAuth2AuthorizationEndpointFilter(AuthenticationManager authenticationManager) {
        this(authenticationManager, DEFAULT_AUTHORIZATION_ENDPOINT_URI);
    }

    /**
     * Constructs an {@code CustomOAuth2AuthorizationEndpointFilter} using the provided parameters.
     *
     * @param authenticationManager the authentication manager
     * @param authorizationEndpointUri the endpoint {@code URI} for authorization requests
     */
    public CustomOAuth2AuthorizationEndpointFilter(AuthenticationManager authenticationManager, String authorizationEndpointUri) {
        Assert.notNull(authenticationManager, "authenticationManager cannot be null");
        Assert.hasText(authorizationEndpointUri, "authorizationEndpointUri cannot be empty");
        this.authenticationManager = authenticationManager;
        this.authorizationEndpointMatcher = createDefaultRequestMatcher(authorizationEndpointUri);
        this.authenticationConverter = new DelegatingAuthenticationConverter(
                Arrays.asList(
                        new CustomOAuth2AuthorizationCodeRequestAuthenticationConverter(),
                        new CustomOAuth2AuthorizationConsentAuthenticationConverter()));
    }

    private static RequestMatcher createDefaultRequestMatcher(String authorizationEndpointUri) {
        RequestMatcher authorizationRequestGetMatcher = new AntPathRequestMatcher(
                authorizationEndpointUri, HttpMethod.GET.name());
        RequestMatcher authorizationRequestPostMatcher = new AntPathRequestMatcher(
                authorizationEndpointUri, HttpMethod.POST.name());
        RequestMatcher openidScopeMatcher = request -> {
            String scope = request.getParameter(OAuth2ParameterNames.SCOPE);
            return StringUtils.hasText(scope) && scope.contains(OidcScopes.OPENID);
        };
        RequestMatcher responseTypeParameterMatcher = request ->
                request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE) != null;

        RequestMatcher authorizationRequestMatcher = new OrRequestMatcher(
                authorizationRequestGetMatcher,
                new AndRequestMatcher(
                        authorizationRequestPostMatcher, responseTypeParameterMatcher, openidScopeMatcher));
        RequestMatcher authorizationConsentMatcher = new AndRequestMatcher(
                authorizationRequestPostMatcher, new NegatedRequestMatcher(responseTypeParameterMatcher));

        return new OrRequestMatcher(authorizationRequestMatcher, authorizationConsentMatcher);
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        if (!this.authorizationEndpointMatcher.matches(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            Authentication authentication = this.authenticationConverter.convert(request);
            if (authentication instanceof AbstractAuthenticationToken) {
                ((AbstractAuthenticationToken) authentication)
                        .setDetails(this.authenticationDetailsSource.buildDetails(request));
            }
            Authentication authenticationResult = this.authenticationManager.authenticate(authentication);

            if (!authenticationResult.isAuthenticated()) {
                filterChain.doFilter(request, response);
                return;
            }

            if (authenticationResult instanceof OAuth2AuthorizationConsentAuthenticationToken) {
                if (this.logger.isTraceEnabled()) {
                    this.logger.trace("Authorization consent is required");
                }

                OAuth2AuthorizationConsentAuthenticationToken consentAuthenticationToken = getOAuth2AuthorizationConsentAuthenticationToken(authentication, (OAuth2AuthorizationConsentAuthenticationToken) authenticationResult);

                this.authenticationSuccessHandler.onAuthenticationSuccess(
                        request, response, consentAuthenticationToken);
                
                return;
            }

            this.authenticationSuccessHandler.onAuthenticationSuccess(
                    request, response, authenticationResult);

        } catch (OAuth2AuthenticationException ex) {
            if (this.logger.isTraceEnabled()) {
                this.logger.trace(LogMessage.format("Authorization request failed: %s", ex.getError()), ex);
            }
            this.authenticationFailureHandler.onAuthenticationFailure(request, response, ex);
        }
    }

    private static OAuth2AuthorizationConsentAuthenticationToken getOAuth2AuthorizationConsentAuthenticationToken(Authentication authentication, OAuth2AuthorizationConsentAuthenticationToken authenticationResult) {
        assert authentication instanceof OAuth2AuthorizationCodeRequestAuthenticationToken;
        Set<String> requestedScopes = ((OAuth2AuthorizationCodeRequestAuthenticationToken) authentication).getScopes();
        Set<String> authorizedScopes = authenticationResult.getScopes();
        String state = authenticationResult.getState();

        Set<String> scopesToAuthorize = new HashSet<>();
        Set<String> scopesPreviouslyAuthorized = new HashSet<>();
        for (String scope : requestedScopes) {
            if (authorizedScopes.contains(scope)) {
                scopesPreviouslyAuthorized.add(scope);
            } else if (!scope.equals(OidcScopes.OPENID)) {
                scopesToAuthorize.add(scope);
            }
        }

        CustomOAuth2AuthorizationConsentAuthenticationToken consentAuthenticationToken = new CustomOAuth2AuthorizationConsentAuthenticationToken(
                DEFAULT_AUTHORIZATION_ENDPOINT_URI
                , ((OAuth2AuthorizationCodeRequestAuthenticationToken) authentication).getClientId()
                , (Authentication) authentication.getPrincipal()
                , state
                , scopesToAuthorize
                , null
        );
        return consentAuthenticationToken;
    }

    /**
     * Sets the {@link AuthenticationDetailsSource} used for building an authentication details instance from {@link HttpServletRequest}.
     *
     * @param authenticationDetailsSource the {@link AuthenticationDetailsSource} used for building an authentication details instance from {@link HttpServletRequest}
     * @since 0.3.1
     */
    public void setAuthenticationDetailsSource(AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
        Assert.notNull(authenticationDetailsSource, "authenticationDetailsSource cannot be null");
        this.authenticationDetailsSource = authenticationDetailsSource;
    }

    /**
     * Sets the {@link AuthenticationConverter} used when attempting to extract an Authorization Request (or Consent) from {@link HttpServletRequest}
     * to an instance of {@link OAuth2AuthorizationCodeRequestAuthenticationToken} or {@link OAuth2AuthorizationConsentAuthenticationToken}
     * used for authenticating the request.
     *
     * @param authenticationConverter the {@link AuthenticationConverter} used when attempting to extract an Authorization Request (or Consent) from {@link HttpServletRequest}
     */
    public void setAuthenticationConverter(AuthenticationConverter authenticationConverter) {
        Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
        this.authenticationConverter = authenticationConverter;
    }

    /**
     * Sets the {@link AuthenticationSuccessHandler} used for handling an {@link OAuth2AuthorizationCodeRequestAuthenticationToken}
     * and returning the {@link OAuth2AuthorizationResponse Authorization Response}.
     *
     * @param authenticationSuccessHandler the {@link AuthenticationSuccessHandler} used for handling an {@link OAuth2AuthorizationCodeRequestAuthenticationToken}
     */
    public void setAuthenticationSuccessHandler(AuthenticationSuccessHandler authenticationSuccessHandler) {
        Assert.notNull(authenticationSuccessHandler, "authenticationSuccessHandler cannot be null");
        this.authenticationSuccessHandler = authenticationSuccessHandler;
    }
    public CustomOAuth2AuthorizationEndpointFilter withAuthenticationSuccessHandler(AuthenticationSuccessHandler authenticationSuccessHandler) {
        Assert.notNull(authenticationSuccessHandler, "authenticationSuccessHandler cannot be null");
        this.authenticationSuccessHandler = authenticationSuccessHandler;
        return this;
    }

    /**
     * Sets the {@link AuthenticationFailureHandler} used for handling an {@link OAuth2AuthorizationCodeRequestAuthenticationException}
     * and returning the {@link OAuth2Error Error Response}.
     *
     * @param authenticationFailureHandler the {@link AuthenticationFailureHandler} used for handling an {@link OAuth2AuthorizationCodeRequestAuthenticationException}
     */
    public void setAuthenticationFailureHandler(AuthenticationFailureHandler authenticationFailureHandler) {
        Assert.notNull(authenticationFailureHandler, "authenticationFailureHandler cannot be null");
        this.authenticationFailureHandler = authenticationFailureHandler;
    }
    
    public CustomOAuth2AuthorizationEndpointFilter withAuthenticationFailureHandler(AuthenticationFailureHandler authenticationFailureHandler) {
        Assert.notNull(authenticationFailureHandler, "authenticationFailureHandler cannot be null");
        this.authenticationFailureHandler = authenticationFailureHandler;
        return this;
    }

}
