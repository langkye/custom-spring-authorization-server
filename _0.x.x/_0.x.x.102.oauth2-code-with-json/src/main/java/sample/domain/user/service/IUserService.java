package sample.domain.user.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
public interface IUserService extends UserDetailsService {
    /**
     * 根据用户名查询用户信息
     * 
     * @param username the username identifying the user whose data is required.
     * @return user info
     */
    UserDetails loadUserByUsername(String username);

    /**
     * 根据手机号查询用户信息
     * 
     * @param username the username identifying the user whose data is required.
     * @return user info
     */
    UserDetails loadUserByTelephone(String username);

    /**
     * 根据客户端id查询用户信息
     * 
     * @param username the username identifying the user whose data is required.
     * @return user info
     */
    UserDetails loadUserByClientId(String username);
}
