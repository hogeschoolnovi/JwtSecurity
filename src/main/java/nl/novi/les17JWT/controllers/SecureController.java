package nl.novi.les17JWT.controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.core.GrantedAuthority;

import java.util.stream.Collectors;

@RestController
public class SecureController {

    private Authentication authentication;

    @GetMapping("/secure")
    public ResponseEntity<String> getSecureData() {
        setAuthentication(SecurityContextHolder.getContext());
        return ResponseEntity.ok("Dit is beveiligde data: " + getAuthenticationText(authentication));
    }

    private void setAuthentication(SecurityContext context) {
        this.authentication =context.getAuthentication();
    }

    @GetMapping("/secure/admin")
    public ResponseEntity<String> getAdminData() {
        setAuthentication(SecurityContextHolder.getContext());
        return ResponseEntity.ok("Dit is beveiligde admin data: " + getAuthenticationText(authentication));
    }

    @GetMapping("/secure/user")
    public ResponseEntity<String> getUserData() {
        setAuthentication(SecurityContextHolder.getContext());
        return ResponseEntity.ok("Dit is beveiligde user data: " +  getAuthenticationText(authentication));
    }

    private String getAuthenticationText(Authentication authentication){

        return authentication.getPrincipal().toString() + " - Authorities: " + getAuthoritiesAsString(authentication) ;
    }

    public String getAuthoritiesAsString(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
    }
}
