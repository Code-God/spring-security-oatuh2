package com.jsure.oauth.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.security.Principal;

/**
 * @Author: wuxiaobiao
 * @Description:
 * @Date: Created in 2018/6/13
 * @Time: 14:33
 * I am a Code Man -_-!
 */
@Controller
public class MainController {

    @GetMapping("/")
    public String root() {
        return "redirect:/index";
    }

    @GetMapping("/index")
    public String index(Principal principal, Model model) {
        if(principal == null ){
            return "index";
        }
        System.out.println(principal.toString());
        model.addAttribute("principal", principal);
        return "index";
    }

    @GetMapping("/403")
    public String accesssDenied() {
        return "403";
    }

    @GetMapping("/signin")
    public String login(Principal principal, Model model) {
        return "login";
    }
}
