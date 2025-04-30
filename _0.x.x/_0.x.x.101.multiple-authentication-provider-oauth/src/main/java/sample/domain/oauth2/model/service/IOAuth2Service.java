package sample.domain.oauth2.model.service;

import sample.config.provider.IAuthRequest;
import sample.domain.oauth2.model.response.OAuth2Response;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
public interface IOAuth2Service {
    OAuth2Response authorize(IAuthRequest request);

    OAuth2Response token(IAuthRequest request);
    
    OAuth2Response consent(IAuthRequest request);
}
