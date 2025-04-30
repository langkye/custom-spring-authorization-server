package sample.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import sample.util.OAuth2ConfigurerUtils;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
@Configuration
public class TokenConfiguration {
    //
    //@Bean
    ////@Lazy
    ////@DependsOn("defaultSecurityConfig")
    //public OAuth2TokenGenerator<? extends OAuth2Token> oAuth2TokenGenerator(HttpSecurity httpSecurity) {
    //    return OAuth2ConfigurerUtils.getTokenGenerator(httpSecurity);
    //}
}
