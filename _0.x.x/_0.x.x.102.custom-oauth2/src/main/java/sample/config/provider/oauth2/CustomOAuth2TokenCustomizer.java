package sample.config.provider.oauth2;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import sample.domain.user.model.entity.Token;

import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
@Configuration
public class CustomOAuth2TokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {
    private final Logger log = LoggerFactory.getLogger(CustomOAuth2TokenCustomizer.class);

    /**
     * Customize the OAuth 2.0 Token attributes.
     *
     * @param context the context containing the OAuth 2.0 Token attributes
     */
    @Override
    public void customize(JwtEncodingContext context) {
        //此处的token字符串是前端拿到的jwtToken信息中解密后的字符串，在这里将自定义jwtToken的实现，将定制jwt的 header 和 claims，将此token存放到 claim 中
        String token = UUID.randomUUID().toString();
        Authentication principal = context.getPrincipal();
        Authentication authorizationGrant = context.getAuthorizationGrant();
        OAuth2Authorization authorization = context.getAuthorization();
        Set<String> authorizedScopes = context.getAuthorizedScopes();
        //ProviderContext providerContext = context.getProviderContext();
        RegisteredClient registeredClient = context.getRegisteredClient();
        //log.info("principal-{}", JSONUtil.toJsonStr(principal));
        //log.info("authorization-{}", JSONUtil.toJsonStr(authorization));
        //log.info("authorizedScopes-{}", JSONUtil.toJsonStr(authorizedScopes));
        //log.info("authorizationGrant-{}", JSONUtil.toJsonStr(authorizationGrant));
        //log.info("providerContext-{}", JSONUtil.toJsonStr(providerContext));
        //log.info("registeredClient-{}", JSONUtil.toJsonStr(registeredClient));
        UserDetails userDetail = null;
        // 目的是为了定制jwt 的header 和 claims
        if (principal instanceof OAuth2ClientAuthenticationToken) {
            //如果当前登录的是client，则进行封装client
            //userDetail = securityAuthUserService.createUserDetailByClientId(registeredClient.getClientId());
        }
        //else if (principal.getPrincipal() instanceof UserDetail) {
            // 如果当前登录的是系统用户，则进行封装userDetail
            //userDetail = securityAuthUserService.createUserDetailByUser((UserDetails) principal.getPrincipal());
        //}
        else if (principal.getPrincipal() instanceof User) {
            //如果当前登录的是系统用户，则进行封装userDetail
            //userDetail = securityAuthUserService.createUserDetailByUser((User) principal.getPrincipal());
        }
        //如果解析失败，则抛出异常信息。
        if (Objects.isNull(userDetail)) {
            log.error("在自定义token实现中, 用户信息解析异常。");
            userDetail = new sample.domain.user.model.entity.User();
        }

        //也需要将此token存放到当前登录用户中，为了在退出登录时进行获取redis中的信息并将其删除
        Token token1 = Token.newInstances();
        token1.setAccessToken(token);
        ((sample.domain.user.model.entity.User)userDetail).setToken(token1);
        //将用户信息放置到redis中，并设置其过期时间为 client中的过期时间
        //strRedisHelper.strSet(LifeSecurityConstants.getUserTokenKey(token), userDetail, registeredClient.getTokenSettings().getAccessTokenTimeToLive().getSeconds(), TimeUnit.SECONDS);
        log.info("生成的用户-token是-{}，此token作为key，用户信息作为value存储到redis中", token);
        //也可以在此处将当前登录用户的信息存放到jwt中，但是这样就不再安全。
        //context.getClaims().claim(LifeSecurityConstants.TOKEN, token).build();
        context.getClaims().claim("access_token", token).build();
    }
}
