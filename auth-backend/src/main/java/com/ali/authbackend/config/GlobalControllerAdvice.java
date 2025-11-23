package com.ali.authbackend.config;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

@ControllerAdvice
@RequiredArgsConstructor
public class GlobalControllerAdvice {

    @Value("${app.name}")
    private String appName;

    @Value("${app.frontend-url}")
    private String frontendUrl;

    @Value("${app.backend-url}")
    private String backendUrl;

    @ModelAttribute
    public void addGlobalAttributes(Model model) {
        model.addAttribute("appName", appName);
        model.addAttribute("frontendUrl", frontendUrl);
        model.addAttribute("backendUrl", backendUrl);
    }
}