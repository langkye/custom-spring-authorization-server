package sample.config.provider.pwd;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import sample.domain.user.model.request.LoginRequest;

import java.security.Principal;
import java.util.Collection;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
public abstract class AbstractCustomAuthenticationToken extends AbstractAuthenticationToken {

    /**
     * Creates a token with the supplied array of authorities.
     *
     * @param authorities the collection of <tt>GrantedAuthority</tt>s for the principal
     *                    represented by this authentication object.
     */
    public AbstractCustomAuthenticationToken(Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
    }

    @Override
    public String getName() {
        if (this.getPrincipal() instanceof UserDetails) {
            return ((UserDetails) this.getPrincipal()).getUsername();
        }
        if (this.getPrincipal() instanceof LoginRequest) {
            return ((LoginRequest) this.getPrincipal()).getName();
        }
        if (this.getPrincipal() instanceof AuthenticatedPrincipal) {
            return ((AuthenticatedPrincipal) this.getPrincipal()).getName();
        }
        if (this.getPrincipal() instanceof Principal) {
            return ((Principal) this.getPrincipal()).getName();
        }
        if (this.getDetails() instanceof LoginRequest) {
            return ((LoginRequest) this.getPrincipal()).getName();
        }
        return null;
    }
}
