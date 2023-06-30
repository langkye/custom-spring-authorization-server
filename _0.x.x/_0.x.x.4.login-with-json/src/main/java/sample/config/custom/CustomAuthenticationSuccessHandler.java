package sample.config.custom;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import sample.domain.Token;
import sample.util.JwtUtil;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * @author langkye
 */
@Component
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    @Resource private ObjectMapper objectMapper;
    @Resource private JwtUtil jwtUtil;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        response.setStatus(HttpStatus.OK.value());
        response.setContentType("application/json");

        Token token = null;
        Object details = authentication.getDetails();
        if (details instanceof UserDetails) {
            UserDetails userDetails = (UserDetails) details;
            token = jwtUtil.createToken(userDetails);
        }
        Object principal = authentication.getPrincipal();
        if (principal instanceof UserDetails) {
            UserDetails userDetails = (UserDetails) principal;
            token = jwtUtil.createToken(userDetails);
        }
        
        if (Objects.isNull(token)) {
            token = Token.newInstances();
        }

        Map<String, Object> data = new HashMap<>();
        data.put("authentication", authentication);
        data.put("token", token);

        Map<String, Object> responseBody = new HashMap<String, Object>() {{
            put("code", HttpStatus.OK.value());
            put("message", "Login successful");
            put("data", data);
        }};

        objectMapper.writeValue(response.getWriter(), responseBody);
    }
}