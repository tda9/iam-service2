package com.da.iam.audit.config;

import com.da.iam.service.CustomUserDetailsService;
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
        // Implement logic to provide current auditor (user)
        return new AuditorAwareImpl(customUserDetailsService);
    }

    @Bean
    public DateTimeProvider dateTimeProvider() {
        // Implement logic to provide current date and time
        return () -> Optional.of(LocalDateTime.now());
    }

}