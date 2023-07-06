package sample.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import sample.domain.user.model.entity.Token;
import sample.domain.user.model.response.UserVo;
import sample.property.AuthorizationProperties;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * @author langkye
 */
@SuppressWarnings({"SpellCheckingInspection", "java:S115"})
@Component
public class JwtUtil {

    private final Key key; // 用于签名 Access Token
    private final Key refreshKey; // 用于签名 Refresh Token
    private final AuthorizationProperties authorizationProperties;

    public JwtUtil(AuthorizationProperties authorizationProperties) {
        this.authorizationProperties = authorizationProperties;
        key = new SecretKeySpec(Base64.getDecoder().decode(authorizationProperties.getJwt().getKey()), "HmacSHA512");
        refreshKey = new SecretKeySpec(Base64.getDecoder().decode(authorizationProperties.getJwt().getRefreshKey()), "HmacSHA512");
    }
    
    public Token createToken(UserDetails userDetails) {
        // cccessToken
        long accessTokenExpireTime = authorizationProperties.getJwt().getAccessTokenExpireTime();
        String accessToken = createJWTToken(userDetails, accessTokenExpireTime);
        
        // refreshToken
        long refreshTokenExpireTime = authorizationProperties.getJwt().getRefreshTokenExpireTime();
        String refreshToken = createJWTToken(userDetails, refreshTokenExpireTime);
        
        return Token.newInstances()
                .withAccessToken(accessToken)
                .withAccessTokenExpiredTime(accessTokenExpireTime)
                .withRefreshToken(refreshToken)
                .withRefreshTokenExpiredTime(refreshTokenExpireTime)
                ;
    }


    public String createJWTToken(UserDetails userDetails, long timeToExpire) {
        return createJWTToken(userDetails, timeToExpire, key);
    }

    /**
     * 根据用户信息生成一个 JWT
     *
     * @param userDetails  用户信息
     * @param timeToExpire 毫秒单位的失效时间
     * @param signKey      签名使用的 key
     * @return JWT
     */
    public String createJWTToken(UserDetails userDetails, long timeToExpire, Key signKey) {
        return Jwts
            .builder()
            .setId("lnkdoc.cn")
            .setSubject(userDetails.getUsername())
            .claim("authorities",
                userDetails.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList()))
                .claim("loginType", ((UserVo)userDetails).getLoginType())
            .setIssuedAt(new Date(System.currentTimeMillis()))
            .setExpiration(new Date(System.currentTimeMillis() + timeToExpire))
            .signWith(signKey, SignatureAlgorithm.HS512).compact();
    }

    public String createAccessToken(UserDetails userDetails) {
        return createJWTToken(userDetails, authorizationProperties.getJwt().getAccessTokenExpireTime());
    }

    public String createRefreshToken(UserDetails userDetails) {
        return createJWTToken(userDetails, authorizationProperties.getJwt().getRefreshTokenExpireTime(), refreshKey);
    }

    public boolean validateAccessToken(String jwtToken) {
        return validateToken(jwtToken, key);
    }

    public boolean validateRefreshToken(String jwtToken) {
        return validateToken(jwtToken, refreshKey);
    }

    public boolean validateToken(String jwtToken, Key signKey) {
        return parseClaims(jwtToken, signKey).isPresent();
    }

    public Optional<Claims> parseClaims(String jwtToken, Key signKey) {
        return Optional.ofNullable(Jwts.parserBuilder().setSigningKey(signKey).build().parseClaimsJws(jwtToken).getBody());
    }

    public boolean validateWithoutExpiration(String jwtToken) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(jwtToken);
            return true;
        } catch (ExpiredJwtException | SignatureException | MalformedJwtException | UnsupportedJwtException | IllegalArgumentException e) {
            if (e instanceof ExpiredJwtException) {
                return true;
            }
        }
        return false;
    }

    public Key getKey() {
        return key;
    }

    public Key getRefreshKey() {
        return refreshKey;
    }
}
