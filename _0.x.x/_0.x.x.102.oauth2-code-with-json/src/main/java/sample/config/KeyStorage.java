package sample.config;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.Requirement;
import com.nimbusds.jose.jwk.*;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import sample.domain.oauth2.model.Oauth2RegisteredKey;
import sample.domain.oauth2.service.IOauth2RegisteredKeyService;
import sample.jose.Jwks;
import sample.property.AuthorizationProperties;

import javax.annotation.Resource;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
@Component
public class KeyStorage {
    private static final Logger log = LoggerFactory.getLogger(KeyStorage.class);
    @Resource private IOauth2RegisteredKeyService oauth2RegisteredKeyService;
    @Resource private AuthorizationProperties authorizationProperties;

    /**
     * 获取所有激活的密钥
     * 
     * @deprecated 使用 {@link #allActiveKeys()}
     * @return keys
     */
    @Deprecated
    public List<JWK> simpleKeys() {
        // FIXME 持久化 密钥
        // 创建 HS512 对称密钥的 JWK
        OctetSequenceKey ak = new OctetSequenceKey.Builder(
                new SecretKeySpec(Base64.getDecoder().decode(authorizationProperties.getJwt().getKey()), "HmacSHA512")
        )
                .keyID("HS512-ACCESS_KEY") // 唯一标识
                .algorithm(JWSAlgorithm.HS512) // 算法标识
                //.algorithm(new Algorithm("HmacSHA512", Requirement.REQUIRED)) // 算法标识
                .build();
        OctetSequenceKey rk = new OctetSequenceKey.Builder(
                new SecretKeySpec(Base64.getDecoder().decode(authorizationProperties.getJwt().getRefreshKey()), "HmacSHA512")
        )
                .keyID("HS512-REFRESH_KEY") // 唯一标识
                .algorithm(JWSAlgorithm.HS512) // 算法标识
                //.algorithm(new Algorithm("HmacSHA512", Requirement.REQUIRED)) // 算法标识
                .build();

        // FIXME 持久化 密钥，避免每次应用重启后 kid（Key ID）变化导致旧令牌无法验证（资源服务器通过 kid 查找对应的公钥验证令牌，若 kid 改变，旧的公钥丢失，旧令牌失效。）
        RSAKey rsaKey = Jwks.generateRsa(); // 生成固定 kid 的 RSA密钥对？
        
        return List.of(rsaKey, ak, rk);
    }
    
    public List<JWK> allActiveKeys() {
        List<Oauth2RegisteredKey> oauth2RegisteredKeys = oauth2RegisteredKeyService.queryAllActiveKeys();

        List<JWK> keys = new ArrayList<>();

        oauth2RegisteredKeys.forEach(keyInfo -> {
            try {
                keys.add(this.transfer2JWK(keyInfo));
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new RuntimeException(e);
            }
        });
        
        return keys;
    }
    
    public List<Key> allActiveSignKeys() {
        List<Oauth2RegisteredKey> oauth2RegisteredKeys = oauth2RegisteredKeyService.queryAllActiveKeys();

        List<Key> keys = new ArrayList<>();

        oauth2RegisteredKeys.forEach(keyInfo -> {
            try {
                keys.add(this.transfer2SignKey(keyInfo));
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new RuntimeException(e);
            }
        });
        
        return keys;
    }
    
    public JWK findKey(String kid) {
        JWK key;
        try {
            key = this.transfer2JWK(oauth2RegisteredKeyService.queryOneByKeyId(kid));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
        return key;
    }
    
    
    
    
    private JWK transfer2JWK(Oauth2RegisteredKey keyInfo) throws NoSuchAlgorithmException, InvalidKeySpecException {
        JWK key;
        
        String algorithm = keyInfo.getAlgorithm();
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.forName(algorithm);
        boolean isHmac = signatureAlgorithm.isHmac();
        boolean isRsa = signatureAlgorithm.isRsa();
        boolean isEllipticCurve = signatureAlgorithm.isEllipticCurve();

        String privateKeyHexString = keyInfo.getPrivateKey();
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyHexString);
        String publicKeyHexString = keyInfo.getPublicKey();

        

        if (isHmac) {
            SecretKey secretKey = Keys.hmacShaKeyFor(privateKeyBytes);
            key = new OctetSequenceKey.Builder(secretKey)
                    .keyID(keyInfo.getKeyId()) // 唯一标识
                    //.algorithm(JWSAlgorithm.HS512) // 算法标识
                    .algorithm(new JWSAlgorithm(algorithm, Requirement.OPTIONAL)) // 算法标识
                    //.algorithm(new Algorithm("HmacSHA512", Requirement.REQUIRED)) // 算法标识
                    .build();
        }
        else if (isRsa) {
            KeyFactory keyFactory = KeyFactory.getInstance(signatureAlgorithm.getFamilyName());
            PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(privateKeyBytes);

            //PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(privateSpec);
            //PrivateKey privateKey = keyFactory.generatePrivate(privateSpec);
            RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privateSpec);

            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyHexString);
            X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(publicKeyBytes);
            //PublicKey publicKey = keyFactory.generatePublic(publicSpec);
            RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(publicSpec);

            //KeyPair keyPair = new KeyPair(publicKey, privateKey);
            //RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            //RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

            key = new RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .keyID(keyInfo.getKeyId())
                    .build();
        }
        else if (isEllipticCurve) {
            //KeyFactory keyFactory = KeyFactory.getInstance(signatureAlgorithm.getFamilyName());
            KeyFactory keyFactory = KeyFactory.getInstance("EC");

            PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(privateKeyBytes);

            ECPrivateKey privateKey = (ECPrivateKey) keyFactory.generatePrivate(privateSpec);

            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyHexString);
            X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(publicKeyBytes);
            ECPublicKey publicKey = (ECPublicKey) keyFactory.generatePublic(publicSpec);

            //KeyPair keyPair = new KeyPair(publicKey, privateKey);
            //RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            //RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

            Curve curve = Curve.forECParameterSpec(publicKey.getParams());
            key = new ECKey.Builder(curve, publicKey)
                    .privateKey(privateKey)
                    .keyID(keyInfo.getKeyId())
                    .build();
        }
        else {
            throw new RuntimeException("Unsupported algorithm: " + algorithm);
        }
        
        return key;
    }
    
    private Key transfer2SignKey(Oauth2RegisteredKey keyInfo) throws NoSuchAlgorithmException, InvalidKeySpecException {
        Key key = null;
        
        String algorithm = keyInfo.getAlgorithm();
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.forName(algorithm);
        boolean isHmac = signatureAlgorithm.isHmac();
        boolean isRsa = signatureAlgorithm.isRsa();
        boolean isEllipticCurve = signatureAlgorithm.isEllipticCurve();

        String privateKeyHexString = keyInfo.getPrivateKey();
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyHexString);
        String publicKeyHexString = keyInfo.getPublicKey();

        

        if (isHmac) {
            key = Keys.hmacShaKeyFor(privateKeyBytes);
        }
        else if (isRsa) {
            KeyFactory keyFactory = KeyFactory.getInstance(signatureAlgorithm.getFamilyName());
            PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(privateKeyBytes);

            //PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(privateSpec);
            //PrivateKey privateKey = keyFactory.generatePrivate(privateSpec);
            //RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privateSpec);

            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyHexString);
            X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(publicKeyBytes);
            //PublicKey publicKey = keyFactory.generatePublic(publicSpec);
            //RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(publicSpec);

            //KeyPair keyPair = new KeyPair(publicKey, privateKey);
            //RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            //RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

            key = keyFactory.generatePrivate(privateSpec);
            //key = keyFactory.generatePublic(publicSpec);
        }
        else if (isEllipticCurve) {
            //KeyFactory keyFactory = KeyFactory.getInstance(signatureAlgorithm.getFamilyName());
            KeyFactory keyFactory = KeyFactory.getInstance("EC");

            PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            //ECPrivateKey privateKey = (ECPrivateKey) keyFactory.generatePrivate(privateSpec);

            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyHexString);
            X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(publicKeyBytes);
            //ECPublicKey publicKey = (ECPublicKey) keyFactory.generatePublic(publicSpec);

            //KeyPair keyPair = new KeyPair(publicKey, privateKey);
            //RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            //RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

            key = keyFactory.generatePrivate(privateSpec);
            //key = keyFactory.generatePublic(publicSpec);
        }
        else {
            throw new RuntimeException("Unsupported algorithm: " + algorithm);
        }
        
        return key;
    }
}
