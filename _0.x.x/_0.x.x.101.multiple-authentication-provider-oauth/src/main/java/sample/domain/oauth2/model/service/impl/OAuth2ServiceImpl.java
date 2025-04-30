package sample.domain.oauth2.model.service.impl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationConsentAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.util.RedirectUrlBuilder;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;
import sample.config.provider.IAuthRequest;
import sample.config.provider.ITokenProvider;
import sample.config.provider.AuthType;
import sample.config.provider.oauth2.AbstractOAuth2AuthenticationProvider;
import sample.domain.oauth2.model.request.OAuth2Request;
import sample.domain.oauth2.model.response.OAuth2Response;
import sample.domain.oauth2.model.service.IOAuth2Service;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import static sample.config.provider.oauth2.AbstractOAuth2AuthenticationProvider.throwInvalidClient;

/**
 * @author langkye
 * 
 * 
 * OAuth默认端点 {@link org.springframework.security.oauth2.server.authorization.web.OAuth2AuthorizationEndpointFilter}
 * @since 1.0.0.RELEASE
 */
@Service
public class OAuth2ServiceImpl implements IOAuth2Service {
    private final Logger logger = LoggerFactory.getLogger(OAuth2ServiceImpl.class);
    
    /**
     * The default endpoint {@code URI} for authorization requests.
     */
    private static final String DEFAULT_AUTHORIZATION_ENDPOINT_URI = "/oauth2/authorize";
    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
    private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();
    @Resource AuthenticationManager authenticationManager;
    private AuthenticationConverter authenticationConverter;
    private AuthenticationSuccessHandler authenticationSuccessHandler;
    private AuthenticationFailureHandler authenticationFailureHandler;
    private String consentPage;
    @Resource private HttpServletRequest httpServletRequest;
    @Resource private HttpServletResponse httpServletResponse;
    private RegisteredClientRepository registeredClientRepository;

    /**
     * {@link org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeAuthenticationConverter#convert(HttpServletRequest)}
     * {@link org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationProvider#authenticate(Authentication)}
     */
    @Override
    public OAuth2Response authorize(IAuthRequest request){
        // 是否进行登录认证（非oauth认证），未登录认证，需先登录（正常应是过滤器拦截，未登录无法进入）
        //      登录认证（前端记住或前端传入，后端返回）需要记住地址栏，以便重定向回来
        
        OAuth2Request oAuth2Request = (OAuth2Request) request;
        this.checkParameter(oAuth2Request);
        
        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(oAuth2Request.getClientId());
        
        if (Objects.isNull(registeredClient)) {
            throwInvalidClient(OAuth2ParameterNames.CLIENT_ID);
        }
        
        
        Number loginTypeNumber = request.getAuthType();

        AuthType loginType = AuthType.of(loginTypeNumber);
        ITokenProvider apply = loginType.getFunction().apply(request);
        
        // OAuth2AuthorizationCodeAuthenticationToken?
        //String code = oAuth2Request.getCode();
        //Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();
        //String redirectUri = oAuth2Request.getRedirectUri();
        //MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getParameters(request);
        //Map<String, Object> additionalParameters = new HashMap<>();
        //		parameters.forEach((key, value) -> {
        //			if (!key.equals(OAuth2ParameterNames.GRANT_TYPE) &&
        //					!key.equals(OAuth2ParameterNames.CLIENT_ID) &&
        //					!key.equals(OAuth2ParameterNames.CODE) &&
        //					!key.equals(OAuth2ParameterNames.REDIRECT_URI)) {
        //				additionalParameters.put(key, (value.size() == 1) ? value.get(0) : value.toArray(new String[0]));
        //			}
        //		});
        // new OAuth2AuthorizationCodeAuthenticationToken(
        //				code, clientPrincipal, redirectUri, additionalParameters);
        
        
        Authentication authenticationResult = this.authenticationManager.authenticate(apply);

        // 客户端认证是否成功（客户端信息）
        if (!authenticationResult.isAuthenticated()) {
            throw new OAuth2AuthenticationException("un authenticate");
        }

        // 需要同意授权：或可从客户端配置入手
        //      授权服务返回授权确认信息
        //      页面携带登录认证的token、用户授权信息（授权域）（以及客户端信息进行认证，或可考虑多因子认证形式进行授权流程），进行授权确认
        Object details = authenticationResult.getDetails();

        return null; // TODO
        
    }

    @Override
    public OAuth2Response token(IAuthRequest request) {
        // TODO
        return null;
    }

    @Override
    public OAuth2Response consent(IAuthRequest request) {
        // 理论上拒绝授权就无需请求了，前端将令牌清除。若请求，服务端将认证因子置为无效。
        // TODO
        return null;
    }


    //~========================================Private Methods========================================~//

    /**
     * sendAuthorizationConsent
     */
    private void sendAuthorizationConsent(HttpServletRequest request, HttpServletResponse response,
                                          OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
                                          OAuth2AuthorizationConsentAuthenticationToken authorizationConsentAuthentication) throws IOException {

        String clientId = authorizationConsentAuthentication.getClientId();
        Authentication principal = (Authentication) authorizationConsentAuthentication.getPrincipal();
        Set<String> requestedScopes = authorizationCodeRequestAuthentication.getScopes();
        Set<String> authorizedScopes = authorizationConsentAuthentication.getScopes();
        String state = authorizationConsentAuthentication.getState();

        if (hasConsentUri()) {
            String redirectUri = UriComponentsBuilder.fromUriString(resolveConsentUri(request))
                    .queryParam(OAuth2ParameterNames.SCOPE, String.join(" ", requestedScopes))
                    .queryParam(OAuth2ParameterNames.CLIENT_ID, clientId)
                    .queryParam(OAuth2ParameterNames.STATE, state)
                    .toUriString();
            this.redirectStrategy.sendRedirect(request, response, redirectUri);
        } else {
            if (this.logger.isTraceEnabled()) {
                this.logger.trace("Displaying generated consent screen");
            }
            DefaultConsentPage.displayConsent(request, response, clientId, principal, requestedScopes, authorizedScopes, state);
        }
    }

    private boolean hasConsentUri() {
        return StringUtils.hasText(this.consentPage);
    }

    private String resolveConsentUri(HttpServletRequest request) {
        if (UrlUtils.isAbsoluteUrl(this.consentPage)) {
            return this.consentPage;
        }
        RedirectUrlBuilder urlBuilder = new RedirectUrlBuilder();
        urlBuilder.setScheme(request.getScheme());
        urlBuilder.setServerName(request.getServerName());
        urlBuilder.setPort(request.getServerPort());
        urlBuilder.setContextPath(request.getContextPath());
        urlBuilder.setPathInfo(this.consentPage);
        return urlBuilder.getUrl();
    }

    /**
     * For internal use only.
     */
    private static class DefaultConsentPage {
        private static final MediaType TEXT_HTML_UTF8 = new MediaType("text", "html", StandardCharsets.UTF_8);

        private static void displayConsent(HttpServletRequest request, HttpServletResponse response,
                                           String clientId, Authentication principal, Set<String> requestedScopes, Set<String> authorizedScopes, String state)
                throws IOException {

            String consentPage = generateConsentPage(request, clientId, principal, requestedScopes, authorizedScopes, state);
            response.setContentType(TEXT_HTML_UTF8.toString());
            response.setContentLength(consentPage.getBytes(StandardCharsets.UTF_8).length);
            response.getWriter().write(consentPage);
        }

        private static String generateConsentPage(HttpServletRequest request,
                                                  String clientId, Authentication principal, Set<String> requestedScopes, Set<String> authorizedScopes, String state) {
            Set<String> scopesToAuthorize = new HashSet<>();
            Set<String> scopesPreviouslyAuthorized = new HashSet<>();
            for (String scope : requestedScopes) {
                if (authorizedScopes.contains(scope)) {
                    scopesPreviouslyAuthorized.add(scope);
                } else if (!scope.equals(OidcScopes.OPENID)) { // openid scope does not require consent
                    scopesToAuthorize.add(scope);
                }
            }

            StringBuilder builder = new StringBuilder();

            builder.append("<!DOCTYPE html>");
            builder.append("<html lang=\"en\">");
            builder.append("<head>");
            builder.append("    <meta charset=\"utf-8\">");
            builder.append("    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, shrink-to-fit=no\">");
            builder.append("    <link rel=\"stylesheet\" href=\"https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css\" integrity=\"sha384-JcKb8q3iqJ61gNV9KGb8thSsNjpSL0n8PARn9HuZOnIxN0hoP+VmmDGMN5t9UJ0Z\" crossorigin=\"anonymous\">");
            builder.append("    <title>Consent required</title>");
            builder.append("	<script>");
            builder.append("		function cancelConsent() {");
            builder.append("			document.consent_form.reset();");
            builder.append("			document.consent_form.submit();");
            builder.append("		}");
            builder.append("	</script>");
            builder.append("</head>");
            builder.append("<body>");
            builder.append("<div class=\"container\">");
            builder.append("    <div class=\"py-5\">");
            builder.append("        <h1 class=\"text-center\">Consent required</h1>");
            builder.append("    </div>");
            builder.append("    <div class=\"row\">");
            builder.append("        <div class=\"col text-center\">");
            builder.append("            <p><span class=\"font-weight-bold text-primary\">" + clientId + "</span> wants to access your account <span class=\"font-weight-bold\">" + principal.getName() + "</span></p>");
            builder.append("        </div>");
            builder.append("    </div>");
            builder.append("    <div class=\"row pb-3\">");
            builder.append("        <div class=\"col text-center\">");
            builder.append("            <p>The following permissions are requested by the above app.<br/>Please review these and consent if you approve.</p>");
            builder.append("        </div>");
            builder.append("    </div>");
            builder.append("    <div class=\"row\">");
            builder.append("        <div class=\"col text-center\">");
            builder.append("            <form name=\"consent_form\" method=\"post\" action=\"" + request.getRequestURI() + "\">");
            builder.append("                <input type=\"hidden\" name=\"client_id\" value=\"" + clientId + "\">");
            builder.append("                <input type=\"hidden\" name=\"state\" value=\"" + state + "\">");

            for (String scope : scopesToAuthorize) {
                builder.append("                <div class=\"form-group form-check py-1\">");
                builder.append("                    <input class=\"form-check-input\" type=\"checkbox\" name=\"scope\" value=\"" + scope + "\" id=\"" + scope + "\">");
                builder.append("                    <label class=\"form-check-label\" for=\"" + scope + "\">" + scope + "</label>");
                builder.append("                </div>");
            }

            if (!scopesPreviouslyAuthorized.isEmpty()) {
                builder.append("                <p>You have already granted the following permissions to the above app:</p>");
                for (String scope : scopesPreviouslyAuthorized) {
                    builder.append("                <div class=\"form-group form-check py-1\">");
                    builder.append("                    <input class=\"form-check-input\" type=\"checkbox\" name=\"scope\" id=\"" + scope + "\" checked disabled>");
                    builder.append("                    <label class=\"form-check-label\" for=\"" + scope + "\">" + scope + "</label>");
                    builder.append("                </div>");
                }
            }

            builder.append("                <div class=\"form-group pt-3\">");
            builder.append("                    <button class=\"btn btn-primary btn-lg\" type=\"submit\" id=\"submit-consent\">Submit Consent</button>");
            builder.append("                </div>");
            builder.append("                <div class=\"form-group\">");
            builder.append("                    <button class=\"btn btn-link regular\" type=\"button\" onclick=\"cancelConsent();\" id=\"cancel-consent\">Cancel</button>");
            builder.append("                </div>");
            builder.append("            </form>");
            builder.append("        </div>");
            builder.append("    </div>");
            builder.append("    <div class=\"row pt-4\">");
            builder.append("        <div class=\"col text-center\">");
            builder.append("            <p><small>Your consent to provide access is required.<br/>If you do not approve, click Cancel, in which case no information will be shared with the app.</small></p>");
            builder.append("        </div>");
            builder.append("    </div>");
            builder.append("</div>");
            builder.append("</body>");
            builder.append("</html>");

            return builder.toString();
        }
    }

    private void checkParameter(OAuth2Request oAuth2Request) {
        if (!StringUtils.hasLength(oAuth2Request.getResponseType())) {
            throwInvalidClient(OAuth2ParameterNames.RESPONSE_TYPE);
        }
        if (!StringUtils.hasLength(oAuth2Request.getClientId())) {
            throwInvalidClient(OAuth2ParameterNames.CLIENT_ID);
        }
        if (!StringUtils.hasLength(oAuth2Request.getScope())) {
            throwInvalidClient(OAuth2ParameterNames.SCOPE);
        }
        if (!StringUtils.hasLength(oAuth2Request.getRedirectUri())) {
            throwInvalidClient(OAuth2ParameterNames.REDIRECT_URI);
        }
    }
}
