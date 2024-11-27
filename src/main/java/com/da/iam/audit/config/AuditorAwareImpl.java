package com.da.iam.audit.config;

import org.springframework.data.domain.AuditorAware;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Objects;
import java.util.Optional;

public class AuditorAwareImpl implements AuditorAware<String> {
    @Override
    public Optional<String> getCurrentAuditor() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (Objects.isNull(authentication)){
            return Optional.of("System");
        }
//        if (authentication.getPrincipal() instanceof JwtUser jwtUser) {
//            return Optional.ofNullable(jwtUser.getUserAccountId().toString());
//        } else {
//            return Optional.of(authentication.getName());
//        }
        return null;
    }
}
