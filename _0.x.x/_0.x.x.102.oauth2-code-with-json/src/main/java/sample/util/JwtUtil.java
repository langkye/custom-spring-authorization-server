package sample.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Component;
import sample.config.KeyStorage;
import sample.domain.user.model.entity.Token;
import sample.domain.user.model.response.UserVo;
import sample.property.AuthorizationProperties;

import javax.annotation.Resource;
import java.security.Key;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * @author langkye
 */
@SuppressWarnings({"SpellCheckingInspection", "java:S115"})
@Component
public class JwtUtil {
    private static final Logger log = LoggerFactory.getLogger(JwtUtil.class);

    private final Key key; // 用于签名 Access Token
    private final Key refreshKey; // 用于签名 Refresh Token
    private final AuthorizationProperties authorizationProperties;
    @Resource
    private JwtEncoder jwtEncoder;
    @Resource
    private JwtDecoder jwtDecoder;

    public JwtUtil(AuthorizationProperties authorizationProperties, KeyStorage keyStorage) {
        this.authorizationProperties = authorizationProperties;

        //key = new SecretKeySpec(Base64.getDecoder().decode(authorizationProperties.getJwt().getKey()), "HmacSHA512");
        //refreshKey = new SecretKeySpec(Base64.getDecoder().decode(authorizationProperties.getJwt().getRefreshKey()), "HmacSHA512");
        
        List<Key> keys = keyStorage.allActiveSignKeys();

        if (!keys.isEmpty()) {
            Random random = new Random();
            int index = random.nextInt(keys.size());

            Key k = keys.get(index);
            key = k;
            refreshKey = k;
        } else {
            throw new RuntimeException("no active sign key");
        }
    }
    
    public Token createToken(UserDetails userDetails) {
        // cccessToken
        long accessTokenExpireTime = authorizationProperties.getJwt().getAccessTokenExpireTime();
        //String accessToken = createJWTToken(userDetails, accessTokenExpireTime);
        String accessToken = createJWTTokenUseEncoder(userDetails, accessTokenExpireTime);
        
        // refreshToken
        long refreshTokenExpireTime = authorizationProperties.getJwt().getRefreshTokenExpireTime();
        //String refreshToken = createRefreshToken(userDetails, refreshTokenExpireTime);
        String refreshToken = createJWTTokenUseEncoder(userDetails, refreshTokenExpireTime);
        
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
    public String createJWTToken0(UserDetails userDetails, long timeToExpire, Key signKey) {
        return Jwts
            .builder()
            .setId("lnkdoc.cn")
            .setSubject(userDetails.getUsername())
            .claim("authorities",
                userDetails.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList()))
                .claim("loginType", ((UserVo)userDetails).getLoginType())
                .claim("username", userDetails.getUsername())
                .claim("telephone", ((UserVo)userDetails).getTelephone())
            .setIssuedAt(new Date(System.currentTimeMillis()))
            .setExpiration(new Date(System.currentTimeMillis() + timeToExpire))
            .signWith(signKey, SignatureAlgorithm.HS512).compact();
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
            .setHeaderParam("typ", "JWT")
            .setHeaderParam("alg", "HS512")
            //.setHeaderParam("keyID", signKey.)
            //.setHeaderParam("kid", "lnkdoc.cn")
            .claim("authorities",
                userDetails.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList()))
                .claim("loginType", ((UserVo)userDetails).getLoginType())
                .claim("username", userDetails.getUsername())
                .claim("telephone", ((UserVo)userDetails).getTelephone())
            .setIssuedAt(new Date(System.currentTimeMillis()))
            .setExpiration(new Date(System.currentTimeMillis() + timeToExpire))
            .signWith(signKey).compact();
    }

    /**
     * 根据用户信息生成一个 JWT
     *
     * @param userDetails  用户信息
     * @param timeToExpire 毫秒单位的失效时间
     * @return JWT
     */
    public String createJWTTokenUseEncoder(UserDetails userDetails, long timeToExpire) {
        // 生成JWT
        JwtClaimsSet claims = JwtClaimsSet.builder()
                //.issuer("https://auth-server.com") // 签发者需与OAuth2令牌一致
                .issuer(authorizationProperties.getServer().getIssuer()) // 签发者需与OAuth2令牌一致
                .subject(userDetails.getUsername())

                .claim("authorities",
                        userDetails.getAuthorities().stream()
                                .map(GrantedAuthority::getAuthority)
                                .collect(Collectors.toList()))
                .claim("loginType", ((UserVo)userDetails).getLoginType())
                .claim("username", userDetails.getUsername())
                .claim("telephone", ((UserVo)userDetails).getTelephone())

                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60 * 30))
                //.expiresAt(Instant.ofEpochSecond(timeToExpire))
                .build();
        Jwt jwt = jwtEncoder.encode(JwtEncoderParameters.from(claims));

        return jwt.getTokenValue();
    }

    public String createAccessToken(UserDetails userDetails) {
        return createJWTToken(userDetails, authorizationProperties.getJwt().getAccessTokenExpireTime());
    }

    public String createRefreshToken(UserDetails userDetails, long timeToExpire) {
        return createJWTToken(userDetails, timeToExpire, refreshKey);
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

    public Optional<Claims> validateTokenUseDecoder(String jwtToken) {
        try {
            Jwt decode = jwtDecoder.decode(jwtToken);
            Map<String, Object> claims = decode.getClaims();
            return Optional.ofNullable(Jwts.claims(claims));
        } catch (JwtException e) {
            log.error("Error validating jwt: {}", e.getLocalizedMessage());
            return Optional.empty();
        }
    }

    public Optional<Claims> parseClaims(String jwtToken, Key signKey) {
        //return Optional.ofNullable(Jwts.parserBuilder().setSigningKey(signKey).build().parseClaimsJws(jwtToken).getBody());
        try {
            return Optional.of(Jwts.parserBuilder().setSigningKey(signKey).build().parseClaimsJws(jwtToken).getBody());
        } catch (ExpiredJwtException | SignatureException | MalformedJwtException | UnsupportedJwtException | IllegalArgumentException e) {
            log.error("Error parsing jwt: {}", e.getLocalizedMessage());
            return Optional.empty();
        }
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
