package sample.config.provider.sms;

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * @author langkye
 */
public final class SmsAuthenticationFilterConfigurer<H extends HttpSecurityBuilder<H>> extends
        AbstractAuthenticationFilterConfigurer<H, SmsAuthenticationFilterConfigurer<H>, SmsAuthenticationFilter> {
	public SmsAuthenticationFilterConfigurer() {
		super(new SmsAuthenticationFilter(), null);
	}
	
	@Override
	protected RequestMatcher createLoginProcessingUrlMatcher(String loginProcessingUrl) {
		return new AntPathRequestMatcher(loginProcessingUrl, "POST");
	}
}
