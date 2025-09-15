package com.github.foamdino.controllers;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ApiController {

    @GetMapping("/")
    public String redirectToAPIDocs() {
        return "redirect:/swagger-ui/index.html";
    }
}
