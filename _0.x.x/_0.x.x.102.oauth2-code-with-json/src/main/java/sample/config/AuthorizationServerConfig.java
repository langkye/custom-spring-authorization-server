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
package sample.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.*;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import sample.config.handler.*;
import sample.config.provider.oauth2.CustomOAuth2AuthorizationEndpointFilter;
import sample.filter.JwtFilter;
import sample.property.AuthorizationProperties;

import javax.annotation.Resource;
import java.util.List;
import java.util.function.Consumer;

/**
 * @author Joe Grandja
 * @since 0.0.1
 */
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {
	@Resource
	private CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler;
	@Resource private CustomAuthenticationFailureHandler customAuthenticationFailureHandler;
	@Resource private CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
	@Resource private CustomAccessDeniedHandler customAccessDeniedHandler;
	@Resource private JwtFilter jwtFilter;
	@Resource private AuthenticationManager authenticationManager;
	@Resource private AuthorizationProperties authorizationProperties;

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
		OAuth2AuthorizationServerConfigurer configurer = http.getConfigurer(OAuth2AuthorizationServerConfigurer.class);
		configurer
				.oidc(oidc ->
						oidc
								.providerConfigurationEndpoint(providerConfigurationEndpoint ->
										providerConfigurationEndpoint.providerConfigurationCustomizer(providerConfiguration -> {})
								)
								.userInfoEndpoint(userInfoEndpoint -> {})
				) // Enable OpenID Connect 1.0
				.authorizationEndpoint(authorizationEndpoint -> 
						authorizationEndpoint
								//.authorizationRequestConverter(customAuthorizationRequestConverter)
								//.authorizationRequestConverters(authorizationRequestConvertersConsumer)
								//.authenticationProvider(authenticationProvider)
								.authenticationProviders(configureAuthenticationValidator())
								//.authenticationProviders(authenticationProvidersConsumer)
								//.consentPage("/oauth2/v1/authorize")
								.authorizationResponseHandler(customAuthenticationSuccessHandler)
								.errorResponseHandler(customAuthenticationFailureHandler)
				)
				//.authorizationConsentService(authorizationConsentService -> {})
		;
		
		// @formatter:off
		http
				.exceptionHandling(exceptions ->
						exceptions.authenticationEntryPoint(customAuthenticationEntryPoint).accessDeniedHandler(customAccessDeniedHandler)
				)
				//.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
				.oauth2ResourceServer((oauth2) -> oauth2
						.jwt(Customizer.withDefaults())
						.withObjectPostProcessor(new BearerTokenAuthenticationFailureHandlerObjectPostProcessor())
				)
				// 禁用csrf
				.csrf().disable()
				.addFilterBefore(new CustomOAuth2AuthorizationEndpointFilter(authenticationManager, authorizationProperties.getServer().getAuthorizationEndpoint())
								.withAuthenticationSuccessHandler(customAuthenticationSuccessHandler)
								.withAuthenticationFailureHandler(customAuthenticationFailureHandler)
						, AbstractPreAuthenticatedProcessingFilter.class)
				.addFilterBefore(jwtFilter, CustomOAuth2AuthorizationEndpointFilter.class)
				//.addFilterBefore(jwtFilter, AbstractPreAuthenticatedProcessingFilter.class)
				// 应用自定义登录处理逻辑
				.apply(new CustomAuthenticationFilterConfigurer<>()).successHandler(customAuthenticationSuccessHandler).failureHandler(customAuthenticationFailureHandler)
		;
		// @formatter:on

		http.build();

		authenticationManager = http.getSharedObject(AuthenticationManager.class);

		return http.getObject();
	}
	
	// @formatter:off






	private Consumer<List<AuthenticationProvider>> configureAuthenticationValidator() {
		return (authenticationProviders) ->
				authenticationProviders.forEach((authenticationProvider) -> {
					if (authenticationProvider instanceof OAuth2AuthorizationCodeRequestAuthenticationProvider) {
						Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> authenticationValidator =
								// Override default redirect_uri validator
								new CustomRedirectUriValidator()
										// Reuse default scope validator
										.andThen(OAuth2AuthorizationCodeRequestAuthenticationValidator.DEFAULT_SCOPE_VALIDATOR);

						((OAuth2AuthorizationCodeRequestAuthenticationProvider) authenticationProvider)
								.setAuthenticationValidator(authenticationValidator);

					}
				});
	}

	static class CustomRedirectUriValidator implements Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> {

		@Override
		public void accept(OAuth2AuthorizationCodeRequestAuthenticationContext authenticationContext) {
			OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
					authenticationContext.getAuthentication();
			RegisteredClient registeredClient = authenticationContext.getRegisteredClient();
			String requestedRedirectUri = authorizationCodeRequestAuthentication.getRedirectUri();

			// Use exact string matching when comparing client redirect URIs against pre-registered URIs
			if (!registeredClient.getRedirectUris().contains(requestedRedirectUri)) {
				OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST);
				throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
			}

		}
	}


}