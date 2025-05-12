package sample.domain.user.service.impl;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;
import sample.config.provider.ITokenProvider;
import sample.config.provider.AuthType;
import sample.domain.user.model.request.LoginRequest;
import sample.domain.user.model.entity.Token;
import sample.domain.user.model.response.UserVo;
import sample.domain.user.service.ILoginService;
import sample.property.AuthorizationProperties;
import sample.util.JwtUtil;

import javax.annotation.Resource;
import java.time.Instant;
import java.util.Objects;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
@Service
public class LoginServiceImpl implements ILoginService {
    //@Resource private Map<String, AuthenticationProvider> authenticationProviders;
    @Resource private AuthenticationManager authenticationManager;
    @Resource private JwtUtil jwtUtil;
    @Resource private JwtEncoder jwtEncoder;
    @Resource private AuthorizationProperties authorizationProperties;
    
    @Override
    public Object login(LoginRequest request) {
        Number loginTypeNumber = request.getAuthType();

        AuthType loginType = AuthType.of(loginTypeNumber);
        ITokenProvider apply = loginType.getFunction().apply(request);

        Authentication authentication = authenticationManager.authenticate(apply);

        Object details = authentication.getDetails();
        ((UserVo)details).setLoginType(request.getAuthType());

        Token token = creatToken(authentication);

        ((UserVo)details).setToken(token);
        //((UserVo)details).setPassword(null);

        ((AbstractAuthenticationToken)authentication).setDetails(details);

        return authentication;
    }
    
    private Token creatToken(Authentication authentication) {
        Token token = null;
        Object details = authentication.getDetails();
        String subject = "";

        if (details instanceof UserDetails) {
            UserDetails userDetails = (UserDetails) details;
            token = jwtUtil.createToken(userDetails);
            subject = userDetails.getUsername();
        }
        Object principal = authentication.getPrincipal();
        if (principal instanceof UserDetails) {
            UserDetails userDetails = (UserDetails) principal;
            token = jwtUtil.createToken(userDetails);
            subject = userDetails.getUsername();
        }

        if (Objects.isNull(token)) {
            token = Token.newInstances();
        }

        // 生成JWT
        JwtClaimsSet claims = JwtClaimsSet.builder()
                //.issuer("https://auth-server.com") // 签发者需与OAuth2令牌一致
                .issuer(authorizationProperties.getServer().getIssuer()) // 签发者需与OAuth2令牌一致
                .subject(subject)
                //.expiresAt(Instant.now().plusSeconds(3600))
                .expiresAt(Instant.ofEpochSecond(authorizationProperties.getJwt().getAccessTokenExpireTime()))
                .build();
        Jwt encodedJwt = jwtEncoder.encode(JwtEncoderParameters.from(claims));

        String tokenValue = encodedJwt.getTokenValue();

        return token;
        //return Token.newInstances().withAccessToken(tokenValue);
    }

}
