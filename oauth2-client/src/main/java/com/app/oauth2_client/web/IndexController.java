package com.app.oauth2_client.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class IndexController {

    @GetMapping(path = "/")
    public String root() {
        return "redirect:/index";
    }

    @GetMapping(path = "/index")
    public String index() {
        return "index";
    }

    @GetMapping("/logged-out")
    public String loggedOut() {
        return "logged-out";
    }
}
