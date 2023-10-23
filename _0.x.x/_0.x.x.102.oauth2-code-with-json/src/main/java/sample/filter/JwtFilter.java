package sample.filter;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import sample.config.handler.CustomAuthenticationFailureHandler;
import sample.config.provider.ITokenProvider;
import sample.config.provider.AuthType;
import sample.domain.user.model.request.LoginRequest;
import sample.property.AuthorizationProperties;
import sample.util.CollectionUtil;
import sample.util.JwtUtil;

import javax.annotation.Resource;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static java.util.stream.Collectors.toList;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
@Component
@Order(1)
public class JwtFilter extends OncePerRequestFilter {
    private final Logger log = LoggerFactory.getLogger(JwtFilter.class);
    @Resource private AuthorizationProperties authorizationProperties;
    @Resource private CustomAuthenticationFailureHandler customAuthenticationFailureHandler;
    @Resource private JwtUtil jwtUtil;
    
    /**
     * Same contract as for {@code doFilter}, but guaranteed to be
     * just invoked once per request within a single request thread.
     * See {@link #shouldNotFilterAsyncDispatch()} for details.
     * <p>Provides HttpServletRequest and HttpServletResponse arguments instead of the
     * default ServletRequest and ServletResponse ones.
     *
     * @param request {@link HttpServletResponse}
     * @param response {@link HttpServletResponse}
     * @param filterChain {@link FilterChain}
     */
    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain) throws ServletException, IOException {
        try {
            if (this.checkToken(request)) {
                Optional<Claims> optional = this.validateToken(request);
                        //.filter(claims -> Objects.nonNull(claims.get("authorities")));
                Optional<Claims> authoritiesOptional = optional.filter(claims -> Objects.nonNull(claims.get("authorities")));
                Optional<Claims> loginTypeOptional = optional.filter(claims -> Objects.nonNull(claims.get("loginType")));
                if (authoritiesOptional.isPresent() && loginTypeOptional.isPresent()) {
                    this.setupSpringAuthentication(optional.get(), loginTypeOptional.get());
                } else {
                    SecurityContextHolder.clearContext();
                }
            }
            filterChain.doFilter(request, response);
        } catch (Exception e) {
            InternalAuthenticationServiceException authenticationServiceException = new InternalAuthenticationServiceException(e.getMessage(), e);
            log.error("", e);
            customAuthenticationFailureHandler.onAuthenticationFailure(request, response, authenticationServiceException);
        }
    }
    
    private boolean checkToken(HttpServletRequest req) {
        String authenticationHeader = req.getHeader(authorizationProperties.getJwt().getHeader());
        return authenticationHeader != null && authenticationHeader.startsWith(authorizationProperties.getJwt().getPrefix());
    }
    
    private Optional<Claims> validateToken(HttpServletRequest req) {
        String jwtToken = req.getHeader(authorizationProperties.getJwt().getHeader()).replace(authorizationProperties.getJwt().getPrefix(), "");
        try {
            return Optional.of(Jwts.parserBuilder().setSigningKey(jwtUtil.getKey()).build().parseClaimsJws(jwtToken).getBody());
        } catch (ExpiredJwtException | SignatureException | MalformedJwtException | UnsupportedJwtException | IllegalArgumentException e) {
            log.error("Error parsing jwt: {}", e.getLocalizedMessage());
            return Optional.empty();
        }
    }
    
    private void setupSpringAuthentication(Claims authoritiesClaims, Claims loginTypeClaims) {
        Collection<?> authoritiesRawList = CollectionUtil.convertObjectToList(authoritiesClaims.get("authorities"));
        Object loginTypeNumber = loginTypeClaims.get("loginType");
        String name = loginTypeClaims.get("name", String.class);
        String username = loginTypeClaims.get("username", String.class);
        String telephone = loginTypeClaims.get("telephone", String.class);
        
        AuthType loginType = AuthType.of((Number) loginTypeNumber);
        
        List<GrantedAuthority> authorities = authoritiesRawList.stream()
                .map(String::valueOf)
                .map(SimpleGrantedAuthority::new)
                .collect(toList());

        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setLoginType((Number) loginTypeNumber);
        loginRequest.setName(name);
        loginRequest.setUsername(username);
        loginRequest.setTelephone(telephone);
        // fixme: 转换为正确的token authentication
        ITokenProvider authentication = loginType.getFunction().apply(loginRequest);
        authentication.setPrincipal(authoritiesClaims.getSubject());
        authentication.setPrincipal(loginRequest);
        authentication.setCredentials(null);
        authentication.setAuthorities(authorities);
        authentication.setAuthenticated(true);
        
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}
