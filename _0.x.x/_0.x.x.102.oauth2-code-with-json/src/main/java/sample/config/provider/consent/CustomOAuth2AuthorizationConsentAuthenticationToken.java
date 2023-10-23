/*
 * Copyright 2020-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample.config.provider.consent;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationConsentAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.util.SpringAuthorizationServerVersion;

import java.util.*;

/**
 * An {@link Authentication} implementation for the OAuth 2.0 Authorization Consent
 * used in the Authorization Code Grant.
 *
 * @author Joe Grandja
 * @since 0.4.0
 * @see CustomOAuth2AuthorizationConsentAuthenticationProvider
 * @see OAuth2AuthorizationCodeRequestAuthenticationProvider
 */
public class CustomOAuth2AuthorizationConsentAuthenticationToken extends OAuth2AuthorizationConsentAuthenticationToken {
	private static final long serialVersionUID = SpringAuthorizationServerVersion.SERIAL_VERSION_UID;

	/**
	 * Constructs an {@code OAuth2AuthorizationConsentAuthenticationToken} using the provided parameters.
	 *
	 * @param authorizationUri the authorization URI
	 * @param clientId the client identifier
	 * @param principal the {@code Principal} (Resource Owner)
	 * @param state the state
	 * @param scopes the requested (or authorized) scope(s)
	 * @param additionalParameters the additional parameters
	 */
	public CustomOAuth2AuthorizationConsentAuthenticationToken(String authorizationUri
			, String clientId
			, Authentication principal
			, String state
			, @Nullable Set<String> scopes
			, @Nullable Map<String
			, Object> additionalParameters) {
		super(authorizationUri, clientId, principal, state, scopes, additionalParameters);
	}

}
