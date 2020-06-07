package test.liuzehua.securitydemo.jwt;

import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.util.Base64;
import java.util.Date;
import java.util.List;

/**
 * JwtTokenProvider
 *
 * @author lynn
 * @version 1.0.0
 * @date 2020/5/13 16:30
 */
@Component
public class JwtTokenProvider {

    @Autowired
    private JwtProperties jwtProperties;

    @Resource
    private UserDetailsService userDetailsService;

    private String secretKey;

    @PostConstruct
    protected void init() {
        secretKey = Base64.getEncoder().encodeToString(jwtProperties.getSecretKey().getBytes());
        System.out.println(jwtProperties.toString());
    }

    public String createToken(String wxOpenId, List<String> roles) {
        //
        Claims claims = Jwts.claims().setSubject(wxOpenId);
        claims.put("roles", roles);

        Date now = new Date();
        Date validity = new Date(now.getTime() + jwtProperties.getValidityInMs());

        return jwtProperties.getHeaderPrefix()+Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();
    }

    public Authentication getAuthentication(String token) {
        UserDetails userDetails = this.userDetailsService.loadUserByUsername(getSubject(token));
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

    private String getSubject(String token) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().getSubject();
    }

    /**
     * parse token
     * @param req
     * @return
     */
    public String parseToken(HttpServletRequest req) {
//        String bearerToken = req.getHeader(jwtProperties.getAuthHeader());
        String bearerToken = req.getParameter("token");
        if (bearerToken != null && bearerToken.startsWith(jwtProperties.getHeaderPrefix())) {
            return bearerToken.substring(jwtProperties.getHeaderPrefix().length());
        }

        return null;
    }

    public boolean validateToken(String token) {
        try {
            Jws<Claims> claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);

            if (claims.getBody().getExpiration().before(new Date())) {
                return false;
            }

            return true;
        } catch (JwtException | IllegalArgumentException e) {
            throw new JwtException("Expired or invalid JWT token");
        }
    }

}

