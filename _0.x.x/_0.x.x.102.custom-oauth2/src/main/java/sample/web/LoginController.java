package sample.web;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import sample.config.handler.CustomAuthenticationFailureHandler;
import sample.config.handler.CustomAuthenticationSuccessHandler;
import sample.domain.user.model.request.LoginRequest;
import sample.domain.user.service.ILoginService;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
@RestController
@RequestMapping("/api/authentication")
public class LoginController {
    private final static Logger logger = LoggerFactory.getLogger(LoginController.class);
    
    @Resource private HttpServletRequest httpServletRequest;
    @Resource private HttpServletResponse httpServletResponse;
    @Resource private CustomAuthenticationFailureHandler customAuthenticationFailureHandler;
    @Resource private CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler;
    @Resource private ILoginService loginService;
    @PostMapping("/login")
    public Object login(@RequestBody LoginRequest request) {
        //try {
        //    Object login = loginService.login(request);
        //    customAuthenticationSuccessHandler.onAuthenticationSuccess(httpServletRequest, httpServletResponse, (Authentication) login);
        //} catch (Exception e) {
        //    logger.error("", e);
        //    customAuthenticationFailureHandler.onAuthenticationFailure(httpServletRequest, httpServletResponse, new InternalAuthenticationServiceException(e.getMessage(), e));
        //}
        return new HashMap<String, Object>() {{
            Object login = null;
            try {
                login = loginService.login(request);
                put("code", 200);
                put("message", "ok");
                put("data", login);
            } catch (Exception e) {
                logger.error("", e);
                put("code", 401);
                put("message", e.getMessage());
                put("data", login);
            }
        }};
    }
}
