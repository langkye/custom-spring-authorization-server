package sample.config.provider.sms;

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
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import sample.domain.user.model.request.LoginRequest;
import sample.domain.user.service.impl.UserDetailsServiceImpl;

import javax.annotation.Resource;
import java.util.Objects;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
@Component
public class SmsAuthenticationProvider implements AuthenticationProvider {
    private final Logger logger = LoggerFactory.getLogger(SmsAuthenticationProvider.class);

    @Resource private UserDetailsServiceImpl userDetailsService;
    
    private MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

    private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();
    
    
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // check parameter
        Assert.isInstanceOf(SmsAuthenticationToken.class, authentication,
                () -> this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.onlySupports",
                        "Only SmsAuthenticationToken is supported"));
        Object principal = authentication.getPrincipal();

        Assert.notNull(principal, "Principal is must be not null");
        Assert.isInstanceOf(LoginRequest.class, principal,
                () -> this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.onlySupports",
                        "Only LoginRequest is supported"));
        LoginRequest request = (LoginRequest) principal;
        String telephone = request.getTelephone();
        String smsCode = request.getSmsCode();
        
        Assert.notNull(telephone, "telephone is must be not null");
        Assert.notNull(smsCode, "smsCode is must be not null");
        
        // load user details
        UserDetails userDetails = userDetailsService.loadUserByTelephone(telephone);
        if (Objects.isNull(userDetails)) {
            throw new UsernameNotFoundException("telephone not exists");
        }
        
        // check credentials
        String cacheSmsCode = smsCode; // todo
        if (!(Objects.nonNull(smsCode) && Objects.equals(smsCode, cacheSmsCode))) {
            throw new BadCredentialsException("Bad sms code");
        }
        
        // success
        SmsAuthenticationToken result = SmsAuthenticationToken.authenticated(
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
        return Objects.equals(SmsAuthenticationToken.class, authentication);
    }
}
