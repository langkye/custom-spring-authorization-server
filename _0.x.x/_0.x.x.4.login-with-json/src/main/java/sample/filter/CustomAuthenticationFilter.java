package sample.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import sample.domain.LoginRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final Logger log = LoggerFactory.getLogger(CustomAuthenticationFilter.class);

    public CustomAuthenticationFilter() {
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        try {
            LoginRequest loginRequest = new ObjectMapper().readValue(request.getInputStream(), LoginRequest.class);
            String username = loginRequest.getUsername();
            String password = loginRequest.getPassword();
            UsernamePasswordAuthenticationToken authRequest = UsernamePasswordAuthenticationToken
                    .unauthenticated(
                            username,
                            password);
            // Allow subclasses to set the "details" property
            setDetails(request, authRequest);
            return this.getAuthenticationManager().authenticate(authRequest);
        } catch (IOException e) {
            log.error("", e);
            return super.attemptAuthentication(request, response);
        }
    }

    @Override
    public void afterPropertiesSet() {
        super.afterPropertiesSet();
    }

}
