package sample.domain.user.model.request;

import sample.config.provider.ILoginRequest;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
public class LoginRequest implements ILoginRequest {
    private Number loginType;
    private String username;
    private String password;
    private String telephone;
    private String smsCode;

    @Override
    public Number getLoginType() {
        return loginType;
    }

    public void setLoginType(Number loginType) {
        this.loginType = loginType;
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
