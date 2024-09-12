package sample.domain.user.model.response;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import org.springframework.security.core.GrantedAuthority;
import sample.domain.user.model.entity.Token;
import sample.domain.user.model.entity.User;

import java.io.Serial;
import java.io.Serializable;
import java.util.Collection;
import java.util.Objects;
import java.util.Optional;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
@JsonTypeInfo(
        //use = JsonTypeInfo.Id.NAME,
        use = JsonTypeInfo.Id.CLASS,
        include = JsonTypeInfo.As.PROPERTY,
        //property = "type"
        property = "@class"
)
@JsonSubTypes({
        @JsonSubTypes.Type(value = UserVo.class, name = "userVo")
})
public class UserVo extends User implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;
    private Collection<GrantedAuthority> authorities;
    private Number loginType;
    private Token token;
    private String password;
    Boolean credentialsNonExpired = true;

    public Number getLoginType() {
        return loginType;
    }

    public void setLoginType(Number loginType) {
        this.loginType = loginType;
    }

    public Token getToken() {
        return token;
    }

    public void setToken(Token token) {
        this.token = token;
    }

    @Override
    public Collection<GrantedAuthority> getAuthorities() {
        return Optional.ofNullable(super.getAuthorities()).orElse(authorities);
    }

    public void setAuthorities(Collection<GrantedAuthority> authorities) {
        this.authorities = authorities;
    }

    @JsonIgnore
    @Override
    public String getPassword() {
        return Optional.ofNullable(super.getPassword()).orElse(password);
    }

    public void setPassword(String password) {
        this.password = password;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return Objects.isNull(credentialsNonExpired) ? super.isCredentialsNonExpired() : credentialsNonExpired;
    }

    public void setCredentialsNonExpired(Boolean credentialsNonExpired) {
        this.credentialsNonExpired = credentialsNonExpired;
    }
}
