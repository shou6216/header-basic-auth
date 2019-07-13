package com.yoshinoda.spring.usage.controller;

import com.yoshinoda.spring.usage.dto.LoginForm;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class LoginController {

    @GetMapping("/login")
    public String index() {
        return "login/index";
    }

    @PostMapping("/authenticate")
    public String login(@Validated @ModelAttribute LoginForm form) {
        System.out.println("LoginController login form=" + form);
        return "forward:/login";
    }
}
