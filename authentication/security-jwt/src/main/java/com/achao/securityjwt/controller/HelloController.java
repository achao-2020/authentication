package com.achao.securityjwt.controller;

/**
 * @author licc3
 * @date 2022-12-15 17:24
 */

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {


    @GetMapping("/hello")
    @PreAuthorize("hasAnyRole('admin')")
    public String hello() {
        return "hello spring security";
    }

}