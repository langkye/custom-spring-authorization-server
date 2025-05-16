package sample.config;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import sample.property.AuthorizationProperties;

import javax.annotation.Resource;
import java.util.*;
import java.util.stream.Collectors;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
@Configuration
@Order(Ordered.HIGHEST_PRECEDENCE)
public class SecurityConfiguration {
    private final Logger logger = LoggerFactory.getLogger(SecurityConfiguration.class);
    @Resource
    private AuthorizationProperties authorizationProperties;
    @Resource
    private KeyStorage keyStorage;

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        //return new BCryptPasswordEncoder();
        //return NoOpPasswordEncoder.getInstance();
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    //@Bean
    //public OAuth2TokenGenerator<? extends OAuth2Token> oAuth2TokenGenerator(HttpSecurity httpSecurity) {
    //    return OAuth2ConfigurerUtils.getTokenGenerator(httpSecurity);
    //}

    @Bean
    public AuthenticationEventPublisher authenticationEventPublisher() {
        return new DefaultAuthenticationEventPublisher() {
            @Override
            public void publishAuthenticationFailure(AuthenticationException exception, Authentication authentication) {
                super.publishAuthenticationFailure(exception, authentication);
                if (exception instanceof OAuth2AuthenticationException) {
                    // 处理OAuth2AuthenticationException异常
                    handleOAuth2AuthenticationException((OAuth2AuthenticationException) exception);
                }
            }
        };
    }

    private void handleOAuth2AuthenticationException(OAuth2AuthenticationException exception) {
        // 在这里添加你的处理逻辑，例如记录错误或通知用户
        logger.info("authenticationEventPublisher -- handleOAuth2AuthenticationException");
        //exception.printStackTrace();
    }


    // @formatter:off
    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("messaging-client")
                .clientSecret("{noop}secret")
                //.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                //.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
                //.clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
                .redirectUri("http://127.0.0.1:8080/authorized")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("message.read")
                .scope("message.write")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();

        // Save registered client in db as if in-memory
        JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
        //registeredClientRepository.save(registeredClient);
        return registeredClientRepository;
    }
    // @formatter:on

    @Bean
    public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        JdbcOAuth2AuthorizationService authorizationService = new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
        /*
        JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper rowMapper = new JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper(registeredClientRepository);
        JdbcOAuth2AuthorizationService.OAuth2AuthorizationParametersMapper oAuth2AuthorizationParametersMapper = new JdbcOAuth2AuthorizationService.OAuth2AuthorizationParametersMapper();

        ObjectMapper objectMapper = new ObjectMapper();
        ClassLoader classLoader = JdbcOAuth2AuthorizationService.class.getClassLoader();
        List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
        objectMapper.registerModules(securityModules);
        objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
        //objectMapper.addMixIn(SmsAuthenticationToken.class, SmsAuthenticationTokenMixin.class);
        objectMapper.registerModule(new CoreJackson2Module()); // <--
        
        rowMapper.setObjectMapper(objectMapper);
        oAuth2AuthorizationParametersMapper.setObjectMapper(objectMapper);
        
        authorizationService.setAuthorizationRowMapper(rowMapper);
        authorizationService.setAuthorizationParametersMapper(oAuth2AuthorizationParametersMapper);
        */
        return authorizationService;
    }

    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        List<JWK> keys = keyStorage.allActiveKeys();
        List<JWK> keys4simple = keyStorage.simpleKeys();
        //keys.addAll(keys4simple);

        JWKSet jwkSet = new JWKSet(keys);
        //JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(jwkSet);
        return (jwkSelector, securityContext) -> {
            // 1. 从 selector 的 matcher 里拿到所有 kid

            List<String> kids = Optional.ofNullable(jwkSelector.getMatcher().getKeyIDs()).orElse(new HashSet<>())
                    .stream()
                    .filter(Objects::nonNull)
                    .toList();

            List<JWK> activeJWKs = jwkSelector.select(jwkSet);
            Map<String, List<JWK>> map = activeJWKs.stream().collect(Collectors.groupingBy(JWK::getKeyID));

            List<JWK> allJWKs = new ArrayList<>(activeJWKs);

            kids.forEach(kid -> {
                if (!map.containsKey(kid)) {
                    allJWKs.add(keyStorage.findKey(kid));
                }
            });

            return allJWKs;
        };
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource());
    }

    @Bean
    public JwtEncoder jwtEncoder() {
        return new NimbusJwtEncoder(jwkSource());
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            // 从JWT声明中提取权限（如scope或roles）FIXME
            List<String> scopes = jwt.getClaim("scope");
            return Optional.ofNullable(scopes).orElse(new ArrayList<>()).stream()
                    .map(scope -> new SimpleGrantedAuthority("SCOPE_" + scope))
                    .collect(Collectors.toList());
        });
        return converter;
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer(authorizationProperties.getServer().getIssuer())
                .jwkSetEndpoint(authorizationProperties.getServer().getJwkSetEndpoint())
                .oidcUserInfoEndpoint(authorizationProperties.getServer().getOidcUserInfoEndpoint())
                .authorizationEndpoint(authorizationProperties.getServer().getAuthorizationEndpoint())
                .tokenEndpoint(authorizationProperties.getServer().getTokenEndpoint())
                .build();
    }
}
