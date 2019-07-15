package com.yoshinoda.spring.usage.security;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public class TokenFilter extends RequestHeaderAuthenticationFilter {

    public TokenFilter() {
        super.setContinueFilterChainOnUnsuccessfulAuthentication(true);
    }

   @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        System.out.println("doFilter");
        String token = resolveToken(request);
        if (token == null) {
            System.out.println("token is null");
            filterChain.doFilter(request, response);
            return;
        }

        try {
            // TODO API実行
            authentication(token);
            User user = new User("guest", "hoge", AuthorityUtils.createAuthorityList("ROLE_USER"));
            SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(user, null, AuthorityUtils.createAuthorityList("ROLE_USER")));
            System.out.println("successsuccesssuccesssuccesssuccesssuccess");

        } catch (Exception e) {
            System.out.println("verify token error");
            SecurityContextHolder.clearContext();
        }
        filterChain.doFilter(request, response);
    }

    private String resolveToken(ServletRequest request) {
        String token = ((HttpServletRequest) request).getHeader("Authorization");
        if (token == null || !token.startsWith("Bearer ")) {
            return null;
        }
        return token.substring(7);
    }

    private void authentication(String token) throws Exception {
        System.out.println("real token=" + token);
        if (token.startsWith("hoge")) {
            return;
        }

        throw new Exception();
    }
}
