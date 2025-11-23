package com.ali.authbackend.controller;

import com.ali.authbackend.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.ui.Model;


@Slf4j
@Controller
@RequestMapping("pages")
@RequiredArgsConstructor
public class WebPagesController {
    private final AuthenticationService authenticationService;

    @Value("${app.frontend-url}")
    private String frontendUrl;

    @Value("${app.backend-url}")
    private String backendUrl;

    @GetMapping("/reset-password-page")
    public String showResetPasswordPage(@RequestParam String token, Model model) {
        boolean valid = authenticationService.validateResetToken(token);

        model.addAttribute("token", token);
        model.addAttribute("valid", valid);
        model.addAttribute("frontendUrl", frontendUrl);
        model.addAttribute("backendUrl", backendUrl);

        return "reset-password-form";
    }

}
