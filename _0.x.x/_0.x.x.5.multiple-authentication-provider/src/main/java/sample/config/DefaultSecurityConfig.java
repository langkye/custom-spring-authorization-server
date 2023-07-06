/*
 * Copyright 2020-2021 the original author or authors.
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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import sample.config.handler.CustomAccessDeniedHandler;
import sample.config.handler.CustomAuthenticationEntryPoint;
import sample.config.handler.CustomAuthenticationFailureHandler;
import sample.config.handler.CustomAuthenticationSuccessHandler;
import sample.config.provider.pwd.PasswordAuthenticationProvider;
import sample.config.provider.sms.SmsAuthenticationProvider;
import sample.filter.JwtFilter;

import javax.annotation.Resource;

import java.util.Arrays;
import java.util.Collections;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * @author Joe Grandja
 * @since 0.1.0
 */
@Configuration
@EnableWebSecurity
// 启用注解权限配置
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
@DependsOn("securityConfiguration")
public class DefaultSecurityConfig {
	@Resource private CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler;
	@Resource private CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
	@Resource private CustomAccessDeniedHandler customAccessDeniedHandler;
	@Resource private CustomAuthenticationFailureHandler customAuthenticationFailureHandler;
	@Resource private Environment environment;
	@Resource private JwtFilter jwtFilter;
	@Resource private SmsAuthenticationProvider smsAuthenticationProvider;
	@Resource private PasswordAuthenticationProvider passwordAuthenticationProvider;

	// @formatter:off
	@Bean
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
		http
				// 禁用session
				.sessionManagement(sessionManagement -> sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				// 异常处理
				.exceptionHandling(exceptions -> exceptions.authenticationEntryPoint(customAuthenticationEntryPoint).accessDeniedHandler(customAccessDeniedHandler))
				// 配置跨域
				.cors(cors -> cors.configurationSource(corsConfigurationSource())) 
				// 请求
				.authorizeRequests(authorizeRequests -> authorizeRequests
						.mvcMatchers("/error", "/api/authentication/login").permitAll()
						.anyRequest().authenticated())
				.formLogin(withDefaults())
				// 禁用表单登录
				.formLogin().disable()
				.logout(AbstractHttpConfigurer::disable)
				// 禁用csrf
				.csrf().disable()
				// token校验
				.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
		;
		return http.build();
	}
	// @formatter:on

	/**
	 * 我们在 Spring Boot 中有几种其他方式配置 CORS
	 * 参见
	 * <a href="https://docs.spring.io/spring/docs/current/spring-framework-reference/web.html#mvc-cors">...</a>
	 * Mvc 的配置方式见 WebMvcConfig 中的代码
	 *
	 * @return CorsConfigurationSource
	 */
	@Bean
	CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		// 允许跨域访问的主机
		if (environment.acceptsProfiles(Profiles.of("dev"))) {
			configuration.setAllowedOrigins(Collections.singletonList("http://localhost:4001"));
		} else {
			configuration.setAllowedOrigins(Collections.singletonList("https://lnkdoc.cn"));
		}
		configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
		configuration.setAllowedHeaders(Collections.singletonList("*"));
		configuration.addExposedHeader("X-Authenticate");
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}
	
	@Autowired
	void configAuthenticationManager(AuthenticationManagerBuilder authenticationManagerBuilder) {
		authenticationManagerBuilder.authenticationProvider(passwordAuthenticationProvider);
		authenticationManagerBuilder.authenticationProvider(smsAuthenticationProvider);
	}
}