package sample.filter;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
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
public class JwtFilter extends OncePerRequestFilter {
    private final Logger log = LoggerFactory.getLogger(JwtFilter.class);
    @Resource private AuthorizationProperties authorizationProperties;
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
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (this.checkToken(request)) {
            Optional<Claims> optional = this.validateToken(request)
                    .filter(claims -> Objects.nonNull(claims.get("authorities")));
            if (optional
                    .isPresent()) {
                this.setupSpringAuthentication(optional.get());
            } else {
                SecurityContextHolder.clearContext();
            }
        }
        filterChain.doFilter(request, response);
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
    
    private void setupSpringAuthentication(Claims claims) {
        Collection<?> rawList = CollectionUtil.convertObjectToList(claims.get("authorities"));
        List<GrantedAuthority> authorities = rawList.stream()
                .map(String::valueOf)
                .map(SimpleGrantedAuthority::new)
                .collect(toList());
        Authentication authentication = new UsernamePasswordAuthenticationToken(claims.getSubject(), null, authorities);
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}
