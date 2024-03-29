package com.progrms.devcource.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class SimpleService {

    public String asyncMethod(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        User principal = authentication != null ? (User) authentication.getPrincipal() : null;
        String name = principal != null ? principal.getUsername() : null;
        log.info("asyncMethod result = {}", name);
        return name;
    }
}
