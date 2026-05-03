package org.example.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Collections;
import java.util.List;
import java.util.Map;

@Controller
public class DashboardController {

    @GetMapping("/dashboard")
    public String dashboard(@AuthenticationPrincipal OidcUser user, Model model) {

        // Basic profile
        model.addAttribute("fullName",          user.getFullName());
        model.addAttribute("givenName",         user.getGivenName());
        model.addAttribute("familyName",        user.getFamilyName());
        model.addAttribute("email",             user.getEmail());
        model.addAttribute("emailVerified",     user.getEmailVerified());
        model.addAttribute("preferredUsername", user.getPreferredUsername());
        model.addAttribute("subject",           user.getSubject());

        // Roles from Keycloak realm_access claim
        Map<String, Object> realmAccess = user.getClaim("realm_access");
        List<String> roles = Collections.emptyList();
        if (realmAccess != null && realmAccess.get("roles") instanceof List<?> raw) {
            roles = raw.stream()
                    .filter(String.class::isInstance)
                    .map(String.class::cast)
                    .toList();
        }
        model.addAttribute("roles", roles);

        // Session / token metadata
        model.addAttribute("sessionState", user.getClaim("session_state"));
        model.addAttribute("issuedAt",     user.getIssuedAt());
        model.addAttribute("expiresAt",    user.getExpiresAt());
        model.addAttribute("issuer",       user.getIssuer());
        model.addAttribute("audience",     user.getAudience());

        // All raw claims
        model.addAttribute("allClaims", user.getClaims());

        return "dashboard";
    }

    // REST endpoint — uses JWT Bearer token
    @GetMapping("/api/me")
    @ResponseBody
    public Map<String, Object> me(@AuthenticationPrincipal Jwt jwt) {
        return Map.of(
                "subject",           jwt.getSubject(),
                "username",          jwt.getClaimAsString("preferred_username"),
                "email",             jwt.getClaimAsString("email"),
                "name",              jwt.getClaimAsString("name"),
                "givenName",         jwt.getClaimAsString("given_name"),
                "familyName",        jwt.getClaimAsString("family_name"),
                "emailVerified",     jwt.getClaimAsBoolean("email_verified"),
                "sessionState",      jwt.getClaimAsString("session_state"),
                "realmAccess",       jwt.getClaim("realm_access")
        );
    }
}