package sample.config.provider.pwd;

import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import sample.config.provider.ILoginRequest;
import sample.config.provider.ITokenProvider;
import sample.config.provider.LoginType;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Objects;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
public class PasswordAuthenticationToken extends AbstractAuthenticationToken implements ITokenProvider {
    private Object credentials;
    private Object principal;
    private Object details;
    private Collection<GrantedAuthority> authorities;

    private boolean authenticated = false;

    public PasswordAuthenticationToken() {
        super(AuthorityUtils.NO_AUTHORITIES);
    }

    public static PasswordAuthenticationToken authenticated(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities, Object details) {
        return new PasswordAuthenticationToken(principal, credentials, authorities, details);
    }

    public static PasswordAuthenticationToken authenticated(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        return new PasswordAuthenticationToken(principal, credentials, authorities);
    }

    public static PasswordAuthenticationToken unauthenticated(Object principal, Object credentials ) {
        return new PasswordAuthenticationToken(principal, credentials);
    }

    public PasswordAuthenticationToken(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(Objects.isNull(authorities) ? AuthorityUtils.NO_AUTHORITIES : new ArrayList<>(authorities));
        this.credentials = credentials;
        this.principal = principal;
        this.authorities = Objects.isNull(authorities) ? AuthorityUtils.NO_AUTHORITIES : new ArrayList<>(authorities);
        this.authenticated = true;
    }

    public PasswordAuthenticationToken(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities, Object details) {
        super(Objects.isNull(authorities) ? AuthorityUtils.NO_AUTHORITIES : new ArrayList<>(authorities));
        this.credentials = credentials;
        this.principal = principal;
        this.authorities = Objects.isNull(authorities) ? AuthorityUtils.NO_AUTHORITIES : new ArrayList<>(authorities);
        this.authenticated = true;
        this.details = details;
    }

    public PasswordAuthenticationToken(Object principal, Object credentials) {
        super(AuthorityUtils.NO_AUTHORITIES);
        this.credentials = credentials;
        this.principal = principal;
        this.authorities = AuthorityUtils.NO_AUTHORITIES;
        this.authenticated = false;
    }

    @Override
    public Object getDetails() {
        return this.details;
    }

    @Override
    public void setDetails(Object details) {
        this.details = details;
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
    public Collection<GrantedAuthority> getAuthorities() {
        return (Collection<GrantedAuthority>) authorities;
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
        return Objects.equals(LoginType.password.getType(), loginType);
    }

    @Override
    public @NonNull LoginType supports() {
        return LoginType.password;
    }

    @Override
    public @NonNull ITokenProvider parser(@NonNull ILoginRequest request) {
        return PasswordAuthenticationToken.unauthenticated(request, request);
    }
}
