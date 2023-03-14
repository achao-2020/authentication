package com.achao.securityjwt.controller;

import com.achao.securityjwt.security.JWTUserDetailsService;
import com.achao.securityjwt.util.JWTUtil;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.ObjectUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;

/**
 * @author licc3
 * @date 2023-3-13 17:24
 */
@RestController
@RequestMapping
public class LoginController {

    @Resource
    private JWTUserDetailsService jwtUserDetailsService;

    @GetMapping("/login")
    public String login(@RequestParam("username") String username, @RequestParam("password") String password) {
        UserDetails userDetails = jwtUserDetailsService.loadUserByUsername(username);
        if (!ObjectUtils.nullSafeEquals(userDetails.getPassword(), password)) {
            throw new RuntimeException("用户名或者密码不正确！");
        }
        // 用户名密码验证成功
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);
        // 这里有认证信息，表示验证已通过
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        return JWTUtil.sign(username , password);
    }
}