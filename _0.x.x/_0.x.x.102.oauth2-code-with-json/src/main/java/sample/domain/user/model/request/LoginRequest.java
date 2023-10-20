package sample.domain.user.model.request;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import sample.config.provider.IAuthRequest;

import java.io.Serializable;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
@JsonSerialize
@JsonDeserialize
public class LoginRequest implements IAuthRequest, Serializable {
    private static final long serialVersionUID = 1L;
    private Integer authType;
    private String username;
    private String password;
    private String telephone;
    private String smsCode;

    @Override
    public Number getAuthType() {
        return authType;
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
