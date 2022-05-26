package com.progrms.devcource.user;

import com.progrms.devcource.jwt.JwtAuthentication;
import com.progrms.devcource.jwt.JwtAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class UserRestController {

    private final UserService userService;

    private final AuthenticationManager authenticationManager;

    public UserRestController(UserService userService, AuthenticationManager authenticationManager) {
        this.userService = userService;
        this.authenticationManager = authenticationManager;
    }

    @PostMapping(path = "/user/login")
    public UserDto login(@RequestBody LoginRequest request) {
        JwtAuthenticationToken authToken = new JwtAuthenticationToken(request.getPrincipal(), request.getCredentials());
        Authentication resultToken = authenticationManager.authenticate(authToken);
        JwtAuthenticationToken authenticated = (JwtAuthenticationToken) resultToken;
        JwtAuthentication principal = (JwtAuthentication) authenticated.getPrincipal();

        User user = (User) authenticated.getDetails();
        return new UserDto(principal.token, principal.username, user.getGroup().getName());
    }


    /**기존
     *
     */
//    private final Jwt jwt;
//
//    private final UserService userService;
//
//    public UserRestController(Jwt jwt, UserService userService) {
//        this.jwt = jwt;
//        this.userService = userService;
//    }

//    /**
//     * 보호받는 엔드포인트 - ROLE_USER 또는 ROLE_ADMIN 권한 필요함
//     *
//     * @return 사용자명
//     */
//    @GetMapping(path = "/user/me")
//    public String me() {
//        return (String) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
//    }
//
//    /**
//     * 주어진 사용자의 JWT 토큰을 출력함
//     *
//     * @param username 사용자명
//     * @return JWT 토큰
//     */
//    @GetMapping(path = "/user/{username}/token")
//    public String getToken(@PathVariable String username) {
//        UserDetails userDetails = userService.loadUserByUsername(username);
//        String[] roles = userDetails.getAuthorities().stream()
//                .map(GrantedAuthority::getAuthority)
//                .toArray(String[]::new);
//        return jwt.sign(Jwt.Claims.from(userDetails.getUsername(), roles));
//    }
//
//    /**
//     * 주어진 JWT 토큰 디코딩 결과를 출력함
//     *
//     * @param token JWT 토큰
//     * @return JWT 디코드 결과
//     */
//    @GetMapping(path = "/user/token/verify")
//    public Map<String, Object> verify(@RequestHeader("token") String token) {
//        return jwt.verify(token).asMap();
//    }

}