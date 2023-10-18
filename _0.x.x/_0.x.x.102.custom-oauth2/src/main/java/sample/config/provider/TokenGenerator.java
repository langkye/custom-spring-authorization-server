package sample.config.provider;

import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.token.*;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
public enum TokenGenerator {
    jwtGenerator(JwtGenerator.class),
    oAuth2AccessTokenGenerator(OAuth2AccessTokenGenerator.class),
    //oAuth2AuthorizationCodeGenerator(OAuth2AuthorizationCodeGenerator.class),
    oAuth2RefreshTokenGenerator(OAuth2RefreshTokenGenerator.class),
    delegatingOAuth2TokenGenerator(DelegatingOAuth2TokenGenerator.class),
    ;
    //JwtGenerator
    private final Class<? extends OAuth2TokenGenerator<? extends OAuth2Token>> tokenGeneratorClazz;

    TokenGenerator(Class<? extends OAuth2TokenGenerator<? extends OAuth2Token>> tokenGeneratorClazz) {
        this.tokenGeneratorClazz = tokenGeneratorClazz;
    }

    public Class<? extends OAuth2TokenGenerator<? extends OAuth2Token>> getTokenGeneratorClazz() {
        return tokenGeneratorClazz;
    }
}
