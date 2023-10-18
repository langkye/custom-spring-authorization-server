package sample.domain.user.model.response;

import sample.domain.user.model.entity.User;

import java.io.Serializable;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
public class UserVo extends User implements Serializable {
    private static final long serialVersionUID = 1L;
    private Number loginType;

    public Number getLoginType() {
        return loginType;
    }

    public void setLoginType(Number loginType) {
        this.loginType = loginType;
    }
}
