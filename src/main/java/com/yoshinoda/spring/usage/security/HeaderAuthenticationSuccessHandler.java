package com.yoshinoda.spring.usage.security;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class HeaderAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication auth) throws IOException, ServletException {
        if (response.isCommitted()) {
            System.out.println("Response has already been committed.");
            return;
        }

        setToken(response, generateToken(auth));
        response.setStatus(HttpStatus.OK.value());
        handle(request, response, auth);
        clearAuthenticationAttributes(request);
    }

    private String generateToken(Authentication auth) {
        //TODO きっとここでTokenを取得する
        User user = (User) auth.getPrincipal();
        System.out.println(user.getUsername());
        String token = "token_hogehoge";
        System.out.println("generate token : " +  token);
        return token;
    }

    private void setToken(HttpServletResponse response, String token) {
        response.setHeader("Authorization", String.format("Bearer %s", token));
    }
}
