package com.okta.developer.gateway.security.oauth2;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * This controller is protected by default, and only used to specify "/authorize" as a login-triggering link.
 */
@Controller
public class AuthRedirectController {

    @GetMapping("/authorize")
    public String redirectToRoot() {
        return "redirect:/";
    }
}
