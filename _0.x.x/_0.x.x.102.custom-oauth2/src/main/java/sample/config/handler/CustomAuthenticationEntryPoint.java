package sample.config.handler;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.*;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.security.auth.login.AccountExpiredException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * @author langkye
 */
@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {
    private static final Logger log = LoggerFactory.getLogger(CustomAuthenticationEntryPoint.class);

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) {
        if (response.isCommitted()) {
            return;
        }

        Throwable throwable = authException.fillInStackTrace();

        String errorMessage = null;

        // BadCredentialsException
        if (authException instanceof BadCredentialsException) {
            //errorMessage = "凭据错误";
            errorMessage = authException.getMessage();
        }
        // 
        else if (authException instanceof UsernameNotFoundException) {
            errorMessage = "用户名不能为空";
        }
        // 
        else if (authException instanceof AuthenticationCredentialsNotFoundException) {
            errorMessage = "凭据不能为空";
        }
        // Other Exception
        else {
            Throwable cause = authException.getCause();

            // JwtValidationException
            if (cause instanceof JwtValidationException) {
                log.warn("JWT Token 过期，具体内容:" + cause.getMessage());
                errorMessage = "无效的token信息";
            }
            // BadJwtException
            else if (cause instanceof BadJwtException) {
                log.warn("JWT 签名异常，具体内容：" + cause.getMessage());
                errorMessage = "无效的token信息";
            }
            // AccountExpiredException
            else if (cause instanceof AccountExpiredException) {
                errorMessage = "账户已过期";
            }
            // LockedException
            else if (cause instanceof LockedException) {
                errorMessage = "账户已被锁定";
            }
            // InsufficientAuthenticationException
            else if (throwable instanceof InsufficientAuthenticationException) {
                String message = throwable.getMessage();
                if (message.contains("Invalid token does not contain resource id")) {
                    errorMessage = "未经授权的资源服务器";
                } else if (message.contains("Full authentication is required to access this resource")) {
                    //errorMessage = "缺少验证信息";
                    errorMessage = "访问令牌无效";
                }
            } 
            // InternalAuthenticationServiceException
            else if (throwable instanceof InternalAuthenticationServiceException) {
                String message = throwable.getMessage();
                if (message.contains("Request processing failed; nested exception is org.springframework.security.authentication.AuthenticationCredentialsNotFoundException: An Authentication object was not found in the SecurityContext")) {
                    //errorMessage = "缺少验证信息";
                    errorMessage = "访问令牌无效";
                }
            }
        }

        if (errorMessage == null) {
            errorMessage = authException.getMessage();
        }
        if (errorMessage == null) {
            errorMessage = authException.getCause().getMessage();
        }

        if (errorMessage == null) {
            errorMessage = "认证失败";
        }

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        //ObjectMapper objectMapper = new ObjectMapper();
        //objectMapper.writeValue(response.getWriter(), WebResponse.failed(
        //        HttpServletResponse.SC_UNAUTHORIZED
        //        , errorMessage
        //));

        String finalErrorMessage = errorMessage;
        Map<String, Object> map = new HashMap<String, Object>(){{
            put("code", HttpServletResponse.SC_UNAUTHORIZED);
            put("message", finalErrorMessage);
        }};

        ObjectMapper objectMapper = new ObjectMapper();
        String resBody;
        try {
            resBody = objectMapper.writeValueAsString(map);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }

        PrintWriter printWriter;
        try {
            printWriter = response.getWriter();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        printWriter.print(resBody);
        printWriter.flush();
        printWriter.close();

    }
}