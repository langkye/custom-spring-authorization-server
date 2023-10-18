package sample.config.handler;

import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationFilter;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
public class BearerTokenAuthenticationFailureHandlerObjectPostProcessor implements ObjectPostProcessor<BearerTokenAuthenticationFilter> {
    @Override
    public <O extends BearerTokenAuthenticationFilter> O postProcess(O filter) {
        filter.setAuthenticationFailureHandler((request, response, exception) -> {
            CustomAuthenticationEntryPoint delegate = new CustomAuthenticationEntryPoint();
            delegate.commence(request, response, exception);
        });
        return filter;
    }
}
