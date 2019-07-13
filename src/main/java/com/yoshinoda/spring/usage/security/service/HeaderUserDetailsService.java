package com.yoshinoda.spring.usage.security.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class HeaderUserDetailsService implements UserDetailsService {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(final String userId) {
        System.out.println("HeaderUserDetailsService loadUserByUsername userId=" + userId);
        String encrypedPwc = passwordEncoder.encode("hoge");

        return new User(userId, encrypedPwc, AuthorityUtils.createAuthorityList("ROLE_USER"));
    }
}
