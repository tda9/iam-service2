package com.da.iam.config;

import com.da.iam.service.CustomUserDetails;
import com.da.iam.service.JWTService;
import com.da.iam.service.UserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

@Component
@RequiredArgsConstructor
public class KeycloakTokenFilter extends OncePerRequestFilter {
    private final UserDetailsService customUserDetailsService;
    private final JWTService jwtService;

    private final JwtDecoder jwtDecoder;
    private  final UserService userService;
    @Value("${application.security.keycloak.enabled}")
    private boolean keycloakEnabled;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws IOException, ServletException {

        if(keycloakEnabled){
            String token = extractToken(request);
            if (token != null && !token.isEmpty()) {
                try {
                    Jwt jwt = jwtDecoder.decode(token);
                    System.out.println(jwt.getClaims());
                    String email = jwt.getClaim("preferred_username");

                    if (email != null && userService.getUserByEmail(email).isPresent()) {
                        // Create authentication object and set it in the security context
                        UserDetails userDetails = customUserDetailsService.loadUserByUsername(email);
                        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                                userDetails, null,userDetails.getAuthorities()
                        );
                        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        SecurityContextHolder.getContext().setAuthentication(authToken);
                    } else {
                        // Handle the case where the email is not found in the database or is invalid
                        response.getWriter().write("Unauthorized: Email not found in database");
                        response.getWriter().flush();
                        return;
                    }
                } catch (Exception e) {
                    response.getWriter().write(e.getMessage());
                    response.getWriter().flush();
                    return;
                }
            }
        }

        filterChain.doFilter(request, response);
    }
    private String extractToken(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7);
        }
        return null;
    }
}
