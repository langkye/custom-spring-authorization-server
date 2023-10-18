package sample.config.provider.sms;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import sample.domain.user.model.request.LoginRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
public class SmsAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    private final Logger log = LoggerFactory.getLogger(SmsAuthenticationProvider.class);
    private static final AntPathRequestMatcher DEFAULT_ANT_PATH_REQUEST_MATCHER = new AntPathRequestMatcher("/api/login/sms", "POST");

    public SmsAuthenticationFilter() {
        super(DEFAULT_ANT_PATH_REQUEST_MATCHER);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        try {
            LoginRequest loginRequest = new ObjectMapper().readValue(request.getInputStream(), LoginRequest.class);
            String telephone = loginRequest.getTelephone();
            String smsCode = loginRequest.getSmsCode();
            SmsAuthenticationToken unauthenticatedToken = SmsAuthenticationToken
                    .unauthenticated(
                            telephone,
                            smsCode);
            SecurityContextHolder.getContext().setAuthentication(unauthenticatedToken);
            //return unauthenticatedToken;


            // Allow subclasses to set the "details" property
            //setDetails(request, authRequest);
            return this.getAuthenticationManager().authenticate(unauthenticatedToken);
        } catch (IOException e) {
            log.error("", e);
            throw new BadCredentialsException("Bad Credentials");
        }
    }

    public SmsAuthenticationFilter withAuthenticationSuccessHandler(AuthenticationSuccessHandler successHandler) {
        super.setAuthenticationSuccessHandler(successHandler);
        return this;
    }

    public SmsAuthenticationFilter withAuthenticationFailureHandler(AuthenticationFailureHandler failureHandler) {
        super.setAuthenticationFailureHandler(failureHandler);
        return this;
    }
}
