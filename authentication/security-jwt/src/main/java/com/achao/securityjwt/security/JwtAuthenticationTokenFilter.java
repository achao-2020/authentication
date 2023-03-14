package com.achao.securityjwt.security;

import com.achao.securityjwt.security.JWTUserDetailsService;
import com.achao.securityjwt.util.JWTUtil;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.annotation.Resource;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author licc3
 * @date 2023-3-13 17:42
 */
@Component
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter{

    @Resource
    private JWTUserDetailsService jwtUserDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String jwt = request.getHeader(JWTUtil.getHeader());
        if(!ObjectUtils.isEmpty(jwt)){
            //根据jwt获取用户名
            String username = JWTUtil.getUsername(jwt);
            //如果可以正确从JWT中提取用户信息，并且该用户未被授权
            if(!ObjectUtils.isEmpty(username) && SecurityContextHolder.getContext().getAuthentication()==null){
                UserDetails userDetails = this.jwtUserDetailsService.loadUserByUsername(username);
                if(JWTUtil.verify(jwt,userDetails.getUsername(), userDetails.getPassword())){
                    //给使用该JWT令牌的用户进行授权
                    UsernamePasswordAuthenticationToken authenticationToken
                            = new UsernamePasswordAuthenticationToken(userDetails,null,
                            userDetails.getAuthorities());
                    authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                }
            }
        }
        filterChain.doFilter(request, response);
    }
}