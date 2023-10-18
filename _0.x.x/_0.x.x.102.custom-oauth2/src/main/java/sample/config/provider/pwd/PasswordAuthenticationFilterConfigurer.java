package sample.config.provider.pwd;

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * @author langkye
 */
public final class PasswordAuthenticationFilterConfigurer<H extends HttpSecurityBuilder<H>> extends
        AbstractAuthenticationFilterConfigurer<H, PasswordAuthenticationFilterConfigurer<H>, PasswordAuthenticationFilter> {
	public PasswordAuthenticationFilterConfigurer() {
		super(new PasswordAuthenticationFilter(), null);
	}
	
	@Override
	protected RequestMatcher createLoginProcessingUrlMatcher(String loginProcessingUrl) {
		return new AntPathRequestMatcher(loginProcessingUrl, "POST");
	}
}
