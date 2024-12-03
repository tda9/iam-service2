package com.da.iam.audit.aspect;


import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.io.IOException;
import java.time.LocalDateTime;

//import java.util.Date;
//
@Slf4j
@Aspect
@Component
public class LoggingAspect {

    @Around("@annotation(org.springframework.web.bind.annotation.PostMapping) || " +
            "@annotation(org.springframework.web.bind.annotation.GetMapping) || " +
            "@annotation(org.springframework.web.bind.annotation.PutMapping) || " +
            "@annotation(org.springframework.web.bind.annotation.DeleteMapping)")
    public Object logRequest(ProceedingJoinPoint joinPoint) throws Throwable {
        HttpServletRequest request =
                ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
        log.info("------------------------------- Request start -------------------------------");
        log.info("User-Agent: {}", request.getHeader("User-Agent"));
        log.info("Remote address: {}", request.getRemoteAddr());
        log.info("Method: {}", request.getMethod());
        log.info("URL: {}", request.getRequestURL());

        Object response;
        try {
            // Proceed with the method execution
            response = joinPoint.proceed();
            // Log response after method execution
            log.info("------------------------------- Response -------------------------------");
            if (response != null) {
                log.info("Response: {}", response.toString());
            } else {
                log.info("Response is null.");
            }
        } catch (Exception e) {
            log.error("Exception while processing request: {}", e.getMessage(), e);
            throw e; // Re-throw the exception for the controller to handle
        }

        log.info("------------------------------- Request end -------------------------------");
        return response;
    }

}
