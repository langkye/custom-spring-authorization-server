package sample.config.provider.pwd;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import sample.domain.user.model.request.LoginRequest;
import sample.domain.user.service.IUserService;

import javax.annotation.Resource;
import java.util.Objects;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
@Component
public class PasswordAuthenticationProvider implements AuthenticationProvider {
    private final Logger logger = LoggerFactory.getLogger(PasswordAuthenticationProvider.class);

    @Resource private IUserService userDetailsService;
    @Resource
    private PasswordEncoder passwordEncoder;
    
    private MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

    private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();
    
    
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // check parameter
        Assert.isInstanceOf(PasswordAuthenticationToken.class, authentication,
                () -> this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.onlySupports",
                        "Only PasswordAuthenticationToken is supported"));
        Object principal = authentication.getPrincipal();

        Assert.notNull(principal, "Principal is must be not null");
        Assert.isInstanceOf(LoginRequest.class, principal,
                () -> this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.onlySupports",
                        "Only LoginRequest is supported"));
        LoginRequest request = (LoginRequest) principal;
        String username = request.getUsername();
        String password = request.getPassword();
        
        Assert.notNull(username, "username is must be not null");
        Assert.notNull(password, "password is must be not null");
        
        // load user details
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        if (Objects.isNull(userDetails)) {
            throw new UsernameNotFoundException("username not exists");
        }
        
        // check credentials
        String savedPassword = userDetails.getPassword();
        if (!passwordEncoder.matches(password, savedPassword)) {
        //if (!PasswordEncoderFactories.createDelegatingPasswordEncoder().matches(password, savedPassword)) {
            throw new BadCredentialsException("Username or password is incorrect");
        }

        // success
        PasswordAuthenticationToken result = PasswordAuthenticationToken.authenticated(
                authentication.getPrincipal()
                ,authentication.getCredentials()
                , this.authoritiesMapper.mapAuthorities(userDetails.getAuthorities())
                //, userDetails
        );
        result.setDetails(userDetails);
        this.logger.debug("Authenticated user");
        return result;
    }
    
    @Override
    public boolean supports(Class<?> authentication) {
        return Objects.equals(PasswordAuthenticationToken.class, authentication);
    }
}
