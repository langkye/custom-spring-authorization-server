package sample.domain.user.model.request;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import sample.config.provider.IAuthRequest;

import java.io.Serializable;
import java.security.Principal;
import java.util.Objects;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
@JsonSerialize
@JsonDeserialize
public class LoginRequest implements IAuthRequest, Serializable {
    private static final long serialVersionUID = 1L;
    private String name;
    private Integer authType;
    private String username;
    private String password;
    private String telephone;
    private String smsCode;

    @Override
    public Number getAuthType() {
        return authType;
    }

    @Override
    public String getName() {
        if (Objects.nonNull(username) && !username.trim().isEmpty()) {
            this.name = username;
        }
        else if (Objects.nonNull(telephone) && !telephone.trim().isEmpty()) {
            this.name =  telephone;
        } else {
            this.name = this.toString();
        }
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setLoginType(Number authType) {
        this.authType = authType.intValue();
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getTelephone() {
        return telephone;
    }

    public void setTelephone(String telephone) {
        this.telephone = telephone;
    }

    public String getSmsCode() {
        return smsCode;
    }

    public void setSmsCode(String smsCode) {
        this.smsCode = smsCode;
    }
}
