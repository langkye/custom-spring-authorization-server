//package sample.config.provider.oauth2.consent;
//
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.context.support.MessageSourceAccessor;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.authentication.AuthenticationProvider;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.AuthenticationException;
//import org.springframework.security.core.SpringSecurityMessageSource;
//import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
//import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
//import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationConsentService;
//import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
//import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
//import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
//import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
//import org.springframework.stereotype.Component;
//import org.springframework.util.Assert;
//import sample.config.provider.oauth2.jwt.OAuth2JwtAuthenticationToken;
//import sample.domain.oauth2.model.request.OAuth2Request;
//import sample.domain.user.service.IUserService;
//
//import javax.annotation.Resource;
//import java.util.Arrays;
//import java.util.Objects;
//import java.util.Set;
//import java.util.stream.Collectors;
//
//import static sample.config.provider.oauth2.AbstractOAuth2AuthenticationProvider.checkInvalidResponseType;
//import static sample.config.provider.oauth2.AbstractOAuth2AuthenticationProvider.throwInvalidClient;
//
///**
// * @author langkye
// * @since 1.0.0.RELEASE
// */
//@Component
//public class OAuth2ConsentAuthenticationProvider implements AuthenticationProvider {
//    private final Logger logger = LoggerFactory.getLogger(OAuth2ConsentAuthenticationProvider.class);
//
//    @Resource private IUserService userDetailsService;
//    @Resource private PasswordEncoder passwordEncoder;
//    @Resource private RegisteredClientRepository registeredClientRepository;
//    @Resource private AuthenticationManager authenticationManager;
//    //@Resource private OAuth2AuthorizationConsentService oAuth2AuthorizationConsentService;
//    @Resource private OAuth2AuthorizationConsentService inMemoryOAuth2AuthorizationConsentService;
//    private MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
//
//    private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();
//    
//    
//    @Override
//    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
//        // check parameter
//        Assert.isInstanceOf(OAuth2JwtAuthenticationToken.class, authentication,
//                () -> this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.onlySupports",
//                        "Only OAuth2JwtAuthenticationToken is supported"));
//        Object principal = authentication.getPrincipal();
//
//        Assert.notNull(principal, "Principal is must be not null");
//        Assert.isInstanceOf(OAuth2Request.class, principal,
//                () -> this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.onlySupports",
//                        "Only OAuth2Request is supported"));
//        OAuth2Request request = (OAuth2Request) principal;
//        String responseType = request.getResponseType();
//        String clientId = request.getClientId();
//        String scope = request.getScope();
//        String redirectUri = request.getRedirectUri();
//        String state = request.getState();
//
//        Assert.notNull(responseType, "responseType is must be not null");
//        Assert.notNull(clientId, "clientId is must be not null");
//        Assert.notNull(scope, "scope is must be not null");
//        Assert.notNull(redirectUri, "redirectUri is must be not null");
//        
//        checkInvalidResponseType(responseType);
//
//        // load registered client
//        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);
//
//        if (Objects.isNull(registeredClient)) {
//            throwInvalidClient(OAuth2ParameterNames.CLIENT_ID);
//        }
//        
//        // match scope
//        Set<String> scopes = registeredClient.getScopes();
//        Set<String> requestScopes = Arrays.stream(scope.split(" ")).filter(it -> it != null  && !"".equals(it.trim())).collect(Collectors.toSet());
//        if (!scopes.containsAll(requestScopes)) {
//            throwInvalidClient(OAuth2ParameterNames.SCOPE);
//        }
//
//        // match redirectUir
//        if (!registeredClient.getRedirectUris().contains(redirectUri.trim())) {
//            throwInvalidClient(OAuth2ParameterNames.REDIRECT_URI);
//        }
//
//        // 是否需求用户授权
//        ClientSettings clientSettings = registeredClient.getClientSettings();
//        if (Objects.nonNull(clientSettings)) {
//            boolean requireAuthorizationConsent = clientSettings.isRequireAuthorizationConsent();
//            if (requireAuthorizationConsent) {
//                authenticationManager.authenticate(OAuth2ConsentAuthenticationToken.unauthenticated(request, request));
//            }
//        }
//
//        // success
//        OAuth2JwtAuthenticationToken result = OAuth2JwtAuthenticationToken.authenticated(
//                authentication.getPrincipal()
//                ,authentication.getCredentials()
//                , this.authoritiesMapper.mapAuthorities(userDetails.getAuthorities())
//                //, userDetails
//        );
//        result.setDetails(userDetails);
//        this.logger.debug("Authenticated user");
//        return result;
//    }
//    
//    @Override
//    public boolean supports(Class<?> authentication) {
//        return Objects.equals(OAuth2JwtAuthenticationToken.class, authentication);
//    }
//}
