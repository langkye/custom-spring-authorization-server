package sample.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
@Configuration
@Order(Ordered.HIGHEST_PRECEDENCE)
public class SecurityConfiguration {
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
    	exception.printStackTrace();
    }
}
