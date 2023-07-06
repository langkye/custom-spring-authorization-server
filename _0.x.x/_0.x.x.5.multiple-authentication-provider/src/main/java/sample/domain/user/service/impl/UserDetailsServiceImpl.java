package sample.domain.user.service.impl;

import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import sample.domain.user.model.response.UserVo;
import sample.domain.user.service.IUserService;

import javax.annotation.Resource;
import java.util.Arrays;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
@Service
public class UserDetailsServiceImpl implements IUserService, UserDetailsService {

    private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();
    @Resource private PasswordEncoder passwordEncoder;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //return new User(username,passwordEncoder.encode(username), AuthorityUtils.createAuthorityList("user"));
        //UserDetails userDetails = User.withDefaultPasswordEncoder()
        //        .username(username)
        //        .password(username)
        //        //.password("{noop}" + username)
        //        //.password(passwordEncoder.encode(username))
        //        .roles("user")
        //        .authorities("user")
        //        .build();
        //return userDetails;

        UserVo user = new UserVo();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(username));
        user.setAuthorities(AuthorityUtils.createAuthorityList("user"));
        return user;
    }

    public UserDetails loadUserByTelephone(String telephone) {
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
        user.setUsername(telephone);
        user.setTelephone(telephone);
        user.setPassword(passwordEncoder.encode(telephone));
        user.setAuthorities(AuthorityUtils.createAuthorityList("user"));
        return user;
    }
}
