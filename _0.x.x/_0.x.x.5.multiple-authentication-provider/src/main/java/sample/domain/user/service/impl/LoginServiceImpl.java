package sample.domain.user.service.impl;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import sample.config.provider.ITokenProvider;
import sample.config.provider.LoginType;
import sample.domain.user.model.request.LoginRequest;
import sample.domain.user.model.entity.Token;
import sample.domain.user.model.response.UserVo;
import sample.domain.user.service.ILoginService;
import sample.util.JwtUtil;

import javax.annotation.Resource;
import java.util.Map;
import java.util.Objects;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
@Service
public class LoginServiceImpl implements ILoginService {
    @Resource private Map<String, AuthenticationProvider> authenticationProviders;
    @Resource private AuthenticationManager authenticationManager;
    @Resource private JwtUtil jwtUtil;
    
    @Override
    public Object login(LoginRequest request) {
        Number loginTypeNumber = request.getLoginType();

        LoginType loginType = LoginType.of(loginTypeNumber);
        ITokenProvider apply = loginType.getFunction().apply(request);

        Authentication authentication = authenticationManager.authenticate(apply);

        Object details = authentication.getDetails();
        ((UserVo)details).setLoginType(request.getLoginType());

        Token token = creatToken(authentication);

        ((UserVo)details).setToken(token);
        //((UserVo)details).setPassword(null);

        ((AbstractAuthenticationToken)authentication).setDetails(details);

        return authentication;
    }
    
    private Token creatToken(Authentication authentication) {
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
        return token;
    }

}
