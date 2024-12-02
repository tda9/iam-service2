package com.da.iam.audit.config;

import com.da.iam.service.CustomUserDetails;
import com.da.iam.service.CustomUserDetailsService;
import org.springframework.data.domain.AuditorAware;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Objects;
import java.util.Optional;

public class AuditorAwareImpl implements AuditorAware<String> {
    private CustomUserDetailsService customUserDetailsService;
    public AuditorAwareImpl(CustomUserDetailsService customUserDetailsService){
        this.customUserDetailsService = customUserDetailsService;
    }
    @Override
    public Optional<String> getCurrentAuditor() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            System.out.println("No authenticated user found");
            return Optional.empty();
        }
        System.out.println("-----------------------Authenticated user: " + (authentication.getPrincipal()).toString());
        //Using Keycloak, the principal is an instance of org.springframework.security.oauth2.jwt.Jwt, need to extract using Jwt Converter
        //Using default Spring Security, the principal is an instance of org.springframework.security.core.userdetails.User:CustomUserDetails(email=tducanh@gmail.com, password=$2a$10$qYXGEMELl.8zlh7JPcgYJOFFT8e6iNt7fmYJtWbpFEClUHrdD2LR2, authorities=[SUPER-GUEST.UPDATE, ROLE_GUEST])

        return Optional.of(authentication.getPrincipal().toString());
    }
}
