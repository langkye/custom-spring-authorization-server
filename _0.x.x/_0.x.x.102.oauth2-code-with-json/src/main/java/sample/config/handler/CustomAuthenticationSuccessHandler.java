package sample.config.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.core.log.LogMessage;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;
import sample.domain.user.model.entity.Token;
import sample.util.JwtUtil;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
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
    private boolean contextRelative;
    
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        response.setStatus(HttpStatus.OK.value());
        response.setContentType("application/json");
        Map<String, Object> data = new HashMap<>();

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
        
        if (authentication instanceof OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication) {
            String code = Objects.requireNonNull(authorizationCodeRequestAuthentication.getAuthorizationCode()).getTokenValue();
            String uri = Objects.requireNonNull(authorizationCodeRequestAuthentication.getRedirectUri());
            String state = authorizationCodeRequestAuthentication.getState();
            UriComponentsBuilder uriBuilder = UriComponentsBuilder
                    .fromUriString(uri)
                    .queryParam(OAuth2ParameterNames.CODE, code);
            if (StringUtils.hasText(state)) {
                uriBuilder.queryParam(OAuth2ParameterNames.STATE, UriUtils.encode(state, StandardCharsets.UTF_8));
            }
            String redirectUri = uriBuilder.build(true).toUriString();		// build(true) -> Components are explicitly encoded
            String redirectUrl = calculateRedirectUrl(request.getContextPath(), redirectUri);
            redirectUrl = response.encodeRedirectURL(redirectUrl);
            String finalRedirectUrl = redirectUrl;
            data.put("code", new HashMap<>(){
                {
                    put("code", code);
                    put("redirectUrl", finalRedirectUrl);
                    put("state", state);
                }
            });
        }

        data.put("authentication", authentication);
        data.put("token", token);

        Map<String, Object> responseBody = new HashMap<String, Object>() {{
            put("code", HttpStatus.OK.value());
            put("message", "Login successful");
            put("data", data);
        }};

        objectMapper.writeValue(response.getWriter(), responseBody);
    }

    String calculateRedirectUrl(String contextPath, String url) {
        if (!UrlUtils.isAbsoluteUrl(url)) {
            if (contextRelative) {
                return url;
            }
            return contextPath + url;
        }
        // Full URL, including http(s)://
        if (!contextRelative) {
            return url;
        }
        Assert.isTrue(url.contains(contextPath), "The fully qualified URL does not include context path.");
        // Calculate the relative URL from the fully qualified URL, minus the last
        // occurrence of the scheme and base context.
        url = url.substring(url.lastIndexOf("://") + 3);
        url = url.substring(url.indexOf(contextPath) + contextPath.length());
        if (url.length() > 1 && url.charAt(0) == '/') {
            url = url.substring(1);
        }
        return url;
    }
}
