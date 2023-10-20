package sample;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.authority.AuthorityUtils;
import sample.domain.user.model.entity.Token;
import sample.domain.user.model.response.UserVo;
import sample.util.JwtUtil;

import javax.annotation.Resource;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
@SpringBootTest(classes = {Oauth2Application.class})
public class JwtUtilTest {
    @Resource private JwtUtil jwtUtil;
    @Resource private ObjectMapper objectMapper;
    @Test
    public void createToken() throws JsonProcessingException {
        UserVo userDetails = new UserVo();
        userDetails.setUsername("user");
        userDetails.setLoginType(10);
        userDetails.setAuthorities(AuthorityUtils.createAuthorityList("USER"));
        Token token = jwtUtil.createToken(userDetails);
        System.out.println();
        System.out.println();
        System.out.println(objectMapper.writeValueAsString(token));
        System.out.println();
        System.out.println();
    }
}
