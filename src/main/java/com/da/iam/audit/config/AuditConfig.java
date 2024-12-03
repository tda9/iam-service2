package com.da.iam.audit.config;

import com.da.iam.service.impl.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.auditing.DateTimeProvider;
import org.springframework.data.domain.AuditorAware;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

import java.time.LocalDateTime;
import java.util.Optional;
@RequiredArgsConstructor
@Configuration
@EnableJpaAuditing(auditorAwareRef = "auditorProvider",
        dateTimeProviderRef = "dateTimeProvider")
public class AuditConfig {
private final CustomUserDetailsService customUserDetailsService;
    @Bean
    public AuditorAware<String> auditorProvider() {
        return new AuditorAwareImpl();
    }

    @Bean
    public DateTimeProvider dateTimeProvider() {
        return () -> Optional.of(LocalDateTime.now());
    }

}