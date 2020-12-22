package org.sid.securityservice.sec;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

public class JwtUtil {
    public static final String Secret="mySecret1234";
    public static final String AUTH_HEADER="Authorization";
    public static final String HEADER_PREFIX="Bearer ";
    public static final long ACCESS_TOKEN_TIME_OUT=1*60*1000;
    public static final long REFRESH_TOKEN_TIME_OUT=10*60*1000;
    public static final String ROLES_CLAIM_NAME="roles";

//    public static String generateAccessToken(String username, String issuer, List<String> roles){
//        Algorithm hmac256 = Algorithm.HMAC256(JwtUtil.Secret);
//        String jwtAccessToken = JWT.create()
//                .withSubject(username)
//                .withIssuer(issuer)
//                .withExpiresAt(new Date(System.currentTimeMillis()+JwtUtil.ACCESS_TOKEN_TIME_OUT))
//                .withClaim(JwtUtil.ROLES_CLAIM_NAME,roles)
//                .sign(hmac256);
//        return jwtAccessToken;
//    }
}
