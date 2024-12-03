package com.da.iam.audit.config;

import com.da.iam.service.impl.CustomUserDetailsService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.AuditorAware;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;
@Slf4j
public class AuditorAwareImpl implements AuditorAware<String> {
    public AuditorAwareImpl(){
    }
    @Override
    public Optional<String> getCurrentAuditor() {
        //tao custom authentication
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            log.error("Error at getCurrentAuditor");
            return Optional.empty();
        }
        log.info("-------------Authenticated user: " + (authentication.getPrincipal()).toString());
        //Using Keycloak, the principal is an instance of org.springframework.security.oauth2.jwt.Jwt, need to extract using Jwt Converter
        //Using default Spring Security, the principal is an instance of org.springframework.security.core.userdetails.User:CustomUserDetails(email=tducanh@gmail.com, password=$2a$10$qYXGEMELl.8zlh7JPcgYJOFFT8e6iNt7fmYJtWbpFEClUHrdD2LR2, authorities=[SUPER-GUEST.UPDATE, ROLE_GUEST])
        return Optional.of(authentication.getName());
    }
}
