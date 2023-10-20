package sample.domain.user.service;

import sample.domain.user.model.request.LoginRequest;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
public interface ILoginService {
    Object login(LoginRequest request);
}
