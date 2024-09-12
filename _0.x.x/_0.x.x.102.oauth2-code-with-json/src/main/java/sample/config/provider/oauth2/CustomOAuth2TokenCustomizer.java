package sample.config.provider.oauth2;

import com.alibaba.fastjson2.JSONObject;
import com.alibaba.fastjson2.JSONWriter;
import com.devskiller.friendly_id.FriendlyId;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import sample.config.provider.ITokenProvider;
import sample.domain.user.model.entity.Token;
import sample.domain.user.service.IUserService;

import javax.annotation.Resource;
import java.util.Objects;
import java.util.Set;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
@Configuration
public class CustomOAuth2TokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {
    private final Logger log = LoggerFactory.getLogger(CustomOAuth2TokenCustomizer.class);
    @Resource
    private IUserService userService;

    /**
     * Customize the OAuth 2.0 Token attributes.
     *
     * @param context the context containing the OAuth 2.0 Token attributes
     */
    @Override
    public void customize(JwtEncodingContext context) {
        OAuth2TokenType tokenType = context.getTokenType();
        log.info("TOKEN_TYPE: `{}`", tokenType.getValue());
        
        // ACCESS_TOKEN
        this.customize4accessToken(context);
        
        // REFRESH_TOKEN
        //this.customize4refreshToken(context);
        
        // ID_TOKEN
        //this.customize4idToken(context);
        
        // CODE
        //this.customize4code(context);
    }
    
    private void customize4accessToken(JwtEncodingContext context) {
        OAuth2TokenType tokenType = context.getTokenType();
        // ACCESS_TOKEN
        if (!Objects.equals(tokenType.getValue(), OAuth2TokenType.ACCESS_TOKEN.getValue())) {
            return;
        }
        log.info("handle {} ...", OAuth2TokenType.ACCESS_TOKEN.getValue());

        Authentication principal = context.getPrincipal();
        log.info("principal type: {}", principal.getClass().getSimpleName());
        //log.info("principal: {}", JSONObject.toJSONString(principal, SerializerFeature.DisableCircularReferenceDetect));
        log.info("principal: {}", JSONObject.toJSONString(principal
                , JSONWriter.Feature.WriteMapNullValue
                //, JSONWriter.Feature.ReferenceDetection // ReferenceDetection	打开引用检测，这个缺省是关闭的，和fastjson 1.x不一致
                //, WriterFeature.DisableCircularReferenceDetect
                , JSONWriter.Feature.LargeObject
                )
        );
        
        //此处的token字符串是前端拿到的jwtToken信息中解密后的字符串，在这里将自定义jwtToken的实现，将定制jwt的 header 和 claims，将此token存放到 claim 中
        String userSessionToken = FriendlyId.createFriendlyId();
        
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
            userDetail = userService.loadUserByClientId(registeredClient.getClientId());
        }
        else if (principal instanceof UserDetails) {
            //如果当前登录的是系统用户，则进行封装userDetail
            //userDetail = securityAuthUserService.createUserDetailByUser((UserDetails) principal.getPrincipal());
            userDetail = userService.loadUserByUsername(((UserDetails) principal).getUsername());
        }
        else if (principal instanceof ITokenProvider) {
            //如果当前登录的是系统用户，则进行封装userDetail
            //userDetail = securityAuthUserService.createUserDetailByUser((UserDetails) principal.getPrincipal());
            //userDetail = userService.loadUserByUsername(((UserDetails) principal.getDetails()).getUsername());
            userDetail = (UserDetails) principal.getDetails();
        }
        
        //如果解析失败，则抛出异常信息。
        if (Objects.isNull(userDetail)) {
            log.error("在自定义token实现中, 用户信息解析异常。");
            //userDetail = new sample.domain.user.model.entity.User();
            userDetail = new sample.domain.user.model.response.UserVo();
        }

        //也需要将此token存放到当前登录用户中，为了在退出登录时进行获取redis中的信息并将其删除
        Token token1 = Token.newInstances().withAccessToken(userSessionToken);
        // fixme 如何优雅属性
        log.error("TODO: 如何优雅设置属性");
        ((sample.domain.user.model.response.UserVo)userDetail).setToken(token1);
        //将用户信息放置到redis中，并设置其过期时间为 client中的过期时间
        //strRedisHelper.strSet(LifeSecurityConstants.getUserTokenKey(token), userDetail, registeredClient.getTokenSettings().getAccessTokenTimeToLive().getSeconds(), TimeUnit.SECONDS);
        // todo 保存session
        log.error("TODO: 保存session");
        log.info("生成的用户-token是-{}，此token作为key，用户信息作为value存储到redis中", userSessionToken);
        //也可以在此处将当前登录用户的信息存放到jwt中，但是这样就不再安全。
        //context.getClaims().claim(LifeSecurityConstants.TOKEN, token).build();
        context.getClaims().claim("access_token", userSessionToken).build();
    }
}
