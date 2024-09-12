package sample.domain.user.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import sample.domain.user.model.entity.User;
import sample.domain.user.model.mapper.UserMapper;
import sample.domain.user.model.response.UserVo;
import sample.domain.user.repository.IUserRepository;
import sample.domain.user.service.IUserService;

import javax.annotation.Resource;
import java.util.Optional;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
@Service
public class UserDetailsServiceImpl implements IUserService, UserDetailsService {

    private static final Logger log = LoggerFactory.getLogger(UserDetailsServiceImpl.class);
    private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();
    
    @Resource private PasswordEncoder passwordEncoder;
    @Resource private IUserRepository userRepository;
    @Resource private ObjectMapper objectMapper;
    @Resource private UserMapper userMapper;

    /**
     * 根据用户名获取用户信息
     * 
     * @param username the username identifying the user whose data is required.
     * @return user info
     * @throws UsernameNotFoundException uex
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> userOptional = userRepository.findByUsername(username);
        return userOptional.map(user -> userMapper.toVo(user)).orElse(null);
    }

    /**
     * 根据手机号获取用户信息
     * 
     * @param telephone the username identifying the user whose data is required.
     * @return user info
     */
    public UserDetails loadUserByTelephone(String telephone) {
        Optional<User> userOptional = userRepository.findByTelephone(telephone);
        return userOptional.map(user -> userMapper.toVo(user)).orElse(null);

        //UserVo user = new UserVo();
        //user.setUsername(telephone);
        //user.setTelephone(telephone);
        //user.setPassword(passwordEncoder.encode(telephone));
        //user.setAuthorities(AuthorityUtils.createAuthorityList("user"));
        //return user;
    }

    /**
     * 根据客户端id获取用户信息
     * 
     * @param clientId the username identifying the user whose data is required.
     * @return user info
     */
    public UserDetails loadUserByClientId(String clientId) {
        log.error("TODO loadUserByClientId: {}", clientId);
        //return new User(username, passwordEncoder.encode(username), AuthorityUtils.createAuthorityList("user"));

        //UserDetails userDetails = User.withDefaultPasswordEncoder()
        //        .username(telephone)
        //        .password(telephone)
        //        //.password("{noop}" + telephone)
        //        //.password(passwordEncoder.encode(telephone))
        //        .roles("user")
        //        .authorities("user")
        //        .build();
        //((sample.domain.user.model.entity.User)userDetails).setTelephone(telephone);
        //return userDetails;

        UserVo user = new UserVo();
        user.setUsername(clientId);
        user.setTelephone(clientId);
        user.setPassword(passwordEncoder.encode(clientId));
        user.setAuthorities(AuthorityUtils.createAuthorityList("user"));
        return user;
    }
}
