package sample.config.provider;

import org.springframework.lang.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
public interface ITokenProvider extends Authentication, CredentialsContainer {
    boolean supports(@NonNull Number loginType);
    @NonNull
    AuthType supports();

    @NonNull ITokenProvider parser(@NonNull IAuthRequest request);

    void setPrincipal(Object subject);

    void setCredentials(Object o);

    void setAuthorities(Collection<GrantedAuthority> authorities);
}
