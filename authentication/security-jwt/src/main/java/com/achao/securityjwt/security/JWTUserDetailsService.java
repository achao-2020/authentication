package com.achao.securityjwt.security;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Component;

/**
 * @author licc3
 * @date 2022-12-15 17:28
 */
@Component
public class JWTUserDetailsService implements UserDetailsService {

    private static final String salt = BCrypt.gensalt();

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserJWTDetail UserDetails = new UserJWTDetail();
        // 请求过来的username进行数据库查询(此处跳过)，springSecurity默认会对比
        UserDetails.setUsername("achao");
        UserDetails.setPassword("achao");
        return UserDetails;
    }
}