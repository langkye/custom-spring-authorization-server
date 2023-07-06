package sample.config.handler;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
@Component
public class CustomAuthenticationFailureHandler extends CustomAuthenticationEntryPoint implements AuthenticationFailureHandler{
    /**
     * Called when an authentication attempt fails.
     *
     * @param request   the request during which the authentication attempt occurred.
     * @param response  the response.
     */
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) {
        commence(request, response ,authException);
    }
}
