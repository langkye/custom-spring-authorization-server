package sample.domain.oauth2.service;

import org.springframework.data.domain.Page;
import sample.domain.oauth2.model.Oauth2RegisteredKey;

import java.util.List;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
public interface IOauth2RegisteredKeyService {
    Page<Oauth2RegisteredKey> queryPage(Oauth2RegisteredKey oauth2RegisteredKey);
    Oauth2RegisteredKey queryOneByKeyId(String keyId);
    List<Oauth2RegisteredKey> queryAllActiveKeys();
    Oauth2RegisteredKey generate(Oauth2RegisteredKey oauth2RegisteredKey);
    Oauth2RegisteredKey active(Oauth2RegisteredKey oauth2RegisteredKey);
    Oauth2RegisteredKey invalid(Oauth2RegisteredKey oauth2RegisteredKey);
    Oauth2RegisteredKey updateExpiresAt(Oauth2RegisteredKey oauth2RegisteredKey);
    Oauth2RegisteredKey dynamicUpdate(Oauth2RegisteredKey oauth2RegisteredKey);
}
