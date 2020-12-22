package org.sid.securityservice.sec.filters;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.sid.securityservice.sec.JwtUtil;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

public class JWTAuthorizationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if(request.getServletPath().equals("/refreshToken") || request.getServletPath().equals("/login")){
            filterChain.doFilter(request,response);
        }
        else{
            String authHeader = request.getHeader(JwtUtil.AUTH_HEADER);
            if(authHeader!=null && authHeader.startsWith(JwtUtil.HEADER_PREFIX)){
                try {
                    String jwt = authHeader.substring(JwtUtil.HEADER_PREFIX.length());
                    Algorithm hmac256 = Algorithm.HMAC256(JwtUtil.Secret);
                    JWTVerifier jwtVerifier = JWT.require(hmac256).build();
                    DecodedJWT decodedJWT = jwtVerifier.verify(jwt);
                    String username = decodedJWT.getSubject();
                    List<String> roles = decodedJWT.getClaim(JwtUtil.ROLES_CLAIM_NAME).asList(String.class);
                    UsernamePasswordAuthenticationToken user = new UsernamePasswordAuthenticationToken(
                            username,
                            null,
                            roles.stream()
                                    .map(r -> new SimpleGrantedAuthority(r))
                                    .collect(Collectors.toList()));
                    SecurityContextHolder.getContext().setAuthentication(user);
                    filterChain.doFilter(request,response);
                }
                catch (Exception e){
                    throw new RuntimeException(e.getMessage());
                }
            }
            else {
                filterChain.doFilter(request,response);
            }
        }

    }
}
