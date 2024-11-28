package com.da.iam.config;

import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver;

@Configuration
public class ApplicationConfig {
    @Bean
    public JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter() {
        return new JwtGrantedAuthoritiesConverter();
    }

    //chu y cai nay, can co cai nay cho secureconfig, neu ko co se ko decode duoc jwt cua keyckoak
    @Bean
    public JwtDecoder jwtDecoder() {
        // Replace the URI with the issuer URI of your Keycloak or other OIDC provider
        return JwtDecoders.fromIssuerLocation("http://localhost:8082/realms/master");
    }

    @Bean
    public ClassLoaderTemplateResolver templateResolver() {
        ClassLoaderTemplateResolver resolver = new ClassLoaderTemplateResolver();
        resolver.setPrefix("templates/"); // Location of thymeleaf template
        resolver.setCacheable(false); // Turning of cache to facilitate template changes
        resolver.setSuffix(".html"); // Template file extension
        resolver.setTemplateMode("HTML"); // Template Type
        resolver.setCharacterEncoding("UTF-8");
        return resolver;
    }

    @Bean
    public SpringTemplateEngine templateEngine() {
        SpringTemplateEngine engine = new SpringTemplateEngine();
        engine.setTemplateResolver(templateResolver());
        return engine;
    }

//    @Bean
//    public Keycloak keycloak() {
//        return KeycloakBuilder.builder()
//                .serverUrl("http://localhost:8082")
//                .realm("iam-service2-realm")
//                .clientId("iam-service2-client")
//                .grantType(OAuth2Constants.PASSWORD)
//                .username("admin")
//                .password("admin")
//                .build();
//    }

}
