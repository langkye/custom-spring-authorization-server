package sample.domain.user.model.response;

import sample.domain.user.model.entity.User;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
public class UserVo extends User {
    private Number loginType;

    public Number getLoginType() {
        return loginType;
    }

    public void setLoginType(Number loginType) {
        this.loginType = loginType;
    }
}
