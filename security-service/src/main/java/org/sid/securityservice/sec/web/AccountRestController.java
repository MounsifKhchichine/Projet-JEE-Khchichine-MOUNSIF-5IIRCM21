package org.sid.securityservice.sec.web;


import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import org.sid.securityservice.sec.JwtUtil;
import org.sid.securityservice.sec.entities.AppRole;
import org.sid.securityservice.sec.entities.AppUser;
import org.sid.securityservice.sec.service.AccountService;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class AccountRestController {
    private AccountService accountService;

    public AccountRestController(AccountService accountService) {
        this.accountService = accountService;
    }

    @GetMapping(path = "/users")
    @PostAuthorize("hasAuthority('USER')")
    public List<AppUser> appUsers() {
        return accountService.listUsers();
    }

    @PostAuthorize("hasAuthority('ADMIN')")
    @PostMapping(path = "/users")
    public AppUser saveUser(@RequestBody AppUser appUser) {
        return accountService.addNewUser(appUser);
    }

    @PostAuthorize("hasAuthority('ADMIN')")
    @PostMapping(path = "/roles")
    public AppRole saveRole(@RequestBody AppRole appRole) {
        return accountService.addNewRole(appRole);
    }

    @PostAuthorize("hasAuthority('ADMIN')")
    @PostMapping(path = "/addRoleToUser")
    public void addRoleToUser(@RequestBody RoleUserForm roleUserForm) {
        accountService.addRoleToUser(roleUserForm.getUsername(), roleUserForm.getRoleName());
    }

    @GetMapping(path = "/refreshToken")
    public Map<String,String> refreshToken(HttpServletRequest request){
        String authHeader = request.getHeader(JwtUtil.AUTH_HEADER);
        if(authHeader!=null && authHeader.startsWith(JwtUtil.HEADER_PREFIX)){
            try {
                String jwtRefreshToken = authHeader.substring(JwtUtil.HEADER_PREFIX.length());
                Algorithm hmac256 = Algorithm.HMAC256(JwtUtil.Secret);
                JWTVerifier jwtVerifier = JWT.require(hmac256).build();
                DecodedJWT decodedJWT = jwtVerifier.verify(jwtRefreshToken);
                String username = decodedJWT.getSubject();
                //Test Revoking Token
                AppUser appUser = accountService.loadUserByUsername(username);
//                String jwtAccessToken = JwtUtil.generateAccessToken(user.getUsername(),
//                        request.getRequestURL().toString(),user.getAuthorities().stream().map(ga -> ga.getAuthority()).collect(Collectors.toList()));
                String jwtAccessToken = JWT.create()
                        .withSubject(appUser.getUsername())
                        .withIssuer(request.getRequestURL().toString())
                        .withExpiresAt(new Date(System.currentTimeMillis()+JwtUtil.ACCESS_TOKEN_TIME_OUT))
                        .withClaim(JwtUtil.ROLES_CLAIM_NAME,appUser.getAppRoles().stream().map(r -> r.getRoleName()).collect(Collectors.toList()))
                        .sign(hmac256);
                Map<String,String> idToken = new HashMap<>();
                idToken.put("access-token",jwtAccessToken);
                idToken.put("refresh-token",jwtRefreshToken);
                return idToken;
            }
            catch (Exception e){
                throw new RuntimeException(e.getMessage());
            }
        }
        else {
            throw new RuntimeException("Refresh token required");
        }
    }
}
@Data
class RoleUserForm{
    private String username;
    private String roleName;
}
