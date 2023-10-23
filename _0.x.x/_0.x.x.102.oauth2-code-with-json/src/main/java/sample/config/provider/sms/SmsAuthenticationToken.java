package sample.config.provider.sms;

import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import sample.config.provider.AuthType;
import sample.config.provider.IAuthRequest;
import sample.config.provider.ITokenProvider;
import sample.config.provider.pwd.AbstractCustomAuthenticationToken;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Objects;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
public class SmsAuthenticationToken extends AbstractCustomAuthenticationToken implements ITokenProvider {
    private Object credentials;
    private Object principal;
    private Object details;
    private Collection<GrantedAuthority> authorities;
    private boolean authenticated = false;
    private String name;

    @Override
    public String getName() {
        name = super.getName();
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public SmsAuthenticationToken() {
        super(AuthorityUtils.NO_AUTHORITIES);
    }

    public static SmsAuthenticationToken authenticated(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        return new SmsAuthenticationToken(principal, credentials, authorities);
    }

    public static SmsAuthenticationToken authenticated(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities, Object details) {
        return new SmsAuthenticationToken(principal, credentials, authorities, details);
    }

    public static SmsAuthenticationToken unauthenticated(Object principal, Object credentials ) {
        return new SmsAuthenticationToken(principal, credentials);
    }

    public SmsAuthenticationToken(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(Objects.isNull(authorities) ? AuthorityUtils.NO_AUTHORITIES : new ArrayList<>(authorities));
        this.principal = principal;
        this.credentials = credentials;
        this.authorities = Objects.isNull(authorities) ? AuthorityUtils.NO_AUTHORITIES : new ArrayList<>(authorities);
        this.authenticated = true;
    }

    public SmsAuthenticationToken(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities, Object details) {
        super(Objects.isNull(authorities) ? AuthorityUtils.NO_AUTHORITIES : new ArrayList<>(authorities));
        this.credentials = credentials;
        this.principal = principal;
        this.authorities = Objects.isNull(authorities) ? AuthorityUtils.NO_AUTHORITIES : new ArrayList<>(authorities);
        this.authenticated = true;
        this.details = details;
    }

    public SmsAuthenticationToken(Object principal, Object credentials) {
        super(AuthorityUtils.NO_AUTHORITIES);
        this.principal = principal;
        this.credentials = credentials;
        this.authenticated = false;
        this.authorities = AuthorityUtils.NO_AUTHORITIES;
    }

    @Override
    public Object getCredentials() {
        return credentials;
    }

    public void setCredentials(Object credentials) {
        this.credentials = credentials;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    public void setPrincipal(Object principal) {
        this.principal = principal;
    }

    @Override
    public Object getDetails() {
        return details;
    }

    @Override
    public void setDetails(Object details) {
        this.details = details;
    }

    @Override
    public Collection<GrantedAuthority> getAuthorities() {
        return authorities;
    }

    public void setAuthorities(Collection<GrantedAuthority> authorities) {
        this.authorities = authorities;
    }

    @Override
    public boolean isAuthenticated() {
        return authenticated;
    }

    @Override
    public void setAuthenticated(boolean authenticated) {
        this.authenticated = authenticated;
    }

    @Override
    public boolean supports(@NonNull Number loginType) {
        return Objects.equals(AuthType.sms.getType(), loginType);
    }

    @Override
    public @NonNull AuthType supports() {
        return AuthType.sms;
    }
    
    @Override
    public @NonNull ITokenProvider parser(@NonNull IAuthRequest request) {
        return SmsAuthenticationToken.unauthenticated(request, request);
    }
}
