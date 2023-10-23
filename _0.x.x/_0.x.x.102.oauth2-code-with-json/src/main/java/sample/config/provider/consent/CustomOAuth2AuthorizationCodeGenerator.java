package sample.config.provider.consent;

import org.springframework.lang.Nullable;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import java.time.Instant;
import java.util.Base64;

public class CustomOAuth2AuthorizationCodeGenerator implements OAuth2TokenGenerator<OAuth2AuthorizationCode> {
	private final StringKeyGenerator authorizationCodeGenerator =
			new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);

	@Nullable
	@Override
	public OAuth2AuthorizationCode generate(OAuth2TokenContext context) {
		if (context.getTokenType() == null ||
				!OAuth2ParameterNames.CODE.equals(context.getTokenType().getValue())) {
			return null;
		}
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(context.getRegisteredClient().getTokenSettings().getAuthorizationCodeTimeToLive());
		return new OAuth2AuthorizationCode(this.authorizationCodeGenerator.generateKey(), issuedAt, expiresAt);
	}

}