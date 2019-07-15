package com.yoshinoda.spring.usage.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@RequestMapping("/")
@Controller
public class HomeController {

    @GetMapping
    public String index() {
        System.out.println("HomeController index");
        return "home/index";
    }

    @GetMapping("hoge1")
    public String hoge1() {
        System.out.println("HomeController hoge1");
        return "home/hoge1";
    }
}
