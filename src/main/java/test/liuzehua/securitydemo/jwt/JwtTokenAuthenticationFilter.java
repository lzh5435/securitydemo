package test.liuzehua.securitydemo.jwt;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * JwtTokenAuthenticationFilter
 *
 * @author lynn
 * @version 1.0.0
 * @date 2020/5/13 16:28
 */
@Component
@Slf4j
public class JwtTokenAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtTokenProvider jwtTokenProvider;


    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        log.debug(">>>>>>>>>>>>>>>>>jwt token authentication filter is entry");
        String token = jwtTokenProvider.parseToken(httpServletRequest);

        if (token != null && jwtTokenProvider.validateToken(token)) {
            log.debug(">>>>>>>>>>>>>>>>>>>>>token is exist ----"+(token != null));
            Authentication auth = jwtTokenProvider.getAuthentication(token);

            if (auth != null) {
                SecurityContextHolder.getContext().setAuthentication(auth);
            }
        }

        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }
}
