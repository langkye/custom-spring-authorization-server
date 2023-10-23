package sample.config.provider.pwd;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.JsonTypeName;
import org.springframework.lang.NonNull;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import sample.config.provider.AuthType;
import sample.config.provider.IAuthRequest;
import sample.config.provider.ITokenProvider;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Objects;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
@JsonTypeInfo(include = JsonTypeInfo.As.WRAPPER_OBJECT, use = JsonTypeInfo.Id.NAME)
@JsonTypeName("PasswordAuthenticationToken")
public class PasswordAuthenticationToken extends AbstractCustomAuthenticationToken implements ITokenProvider {
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

    @Override
    public void setCredentials(Object credentials) {
        this.credentials = credentials;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    @Override
    public void setPrincipal(Object principal) {
        this.principal = principal;
    }

    @Override
    public Collection<GrantedAuthority> getAuthorities() {
        return (Collection<GrantedAuthority>) authorities;
    }

    @Override
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
        return Objects.equals(AuthType.password.getType(), loginType);
    }

    @Override
    public @NonNull AuthType supports() {
        return AuthType.password;
    }

    @Override
    public @NonNull ITokenProvider parser(@NonNull IAuthRequest request) {
        return PasswordAuthenticationToken.unauthenticated(request, request);
    }
}
