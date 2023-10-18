package sample.config.handler;

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
/**
 * @author langkye
 */
public final class CustomAuthenticationFilterConfigurer<H extends HttpSecurityBuilder<H>> extends
        AbstractAuthenticationFilterConfigurer<H, CustomAuthenticationFilterConfigurer<H>, CustomAuthenticationFilter> {
	public CustomAuthenticationFilterConfigurer() {
		super(new CustomAuthenticationFilter(), null);
	}
	
	@Override
	protected RequestMatcher createLoginProcessingUrlMatcher(String loginProcessingUrl) {
		return new AntPathRequestMatcher(loginProcessingUrl, "POST");
	}
}
