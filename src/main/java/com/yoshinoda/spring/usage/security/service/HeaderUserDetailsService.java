package com.yoshinoda.spring.usage.security.service;

import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

@Service
public class HeaderUserDetailsService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(final String userId) {
        System.out.println("HeaderUserDetailsService loadUserByUsername userId=" + userId);
        // emailでデータベースからユーザーエンティティを検索する
        return new User(userId, "", AuthorityUtils.createAuthorityList("ROLE_USER"));
    }
}
