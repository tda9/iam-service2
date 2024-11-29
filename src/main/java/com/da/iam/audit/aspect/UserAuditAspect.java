//package com.da.iam.audit.aspect;
//
//import com.da.iam.audit.repo.UserAuditRepository;
//import jakarta.servlet.http.HttpServletRequest;
//import org.aspectj.lang.ProceedingJoinPoint;
//import org.aspectj.lang.annotation.*;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.stereotype.Component;
//import org.springframework.web.context.request.RequestContextHolder;
//import org.springframework.web.context.request.ServletRequestAttributes;
//
//import java.io.IOException;
//import java.time.LocalDateTime;
//
////import java.util.Date;
////
//@Aspect
//@Component
//public class UserAuditAspect {
//
//    @Autowired
//    private UserAuditRepository userAuditRepository;
//
//    @Around("@annotation(org.springframework.web.bind.annotation.PostMapping) || " +
//            "@annotation(org.springframework.web.bind.annotation.GetMapping) || " +
//            "@annotation(org.springframework.web.bind.annotation.PutMapping) || " +
//            "@annotation(org.springframework.web.bind.annotation.DeleteMapping)")
//    public Object logRequest(ProceedingJoinPoint joinPoint) throws Throwable {
//        // Extract the HTTP request data
//        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
//        // Capture the response object (after the method executes)
//        Object response = null;
//        try {
//            // Proceed with the method execution
//            response = joinPoint.proceed();
//        } catch (Exception e) {
//            // Log the error, if any
//            logActivity(request, response);
//            throw e; // rethrow the exception to be handled by the controller
//        }
//
//        // Log the successful request
//        logActivity(request, response);
//        return response;
//    }
//
//    private void logActivity(HttpServletRequest request,Object response) throws IOException {
//        String userAgent = request.getHeader("User-Agent");
//        String ip = request.getRemoteAddr();
//        String requestMethod = request.getMethod();
//        String url = request.getRequestURL().toString();
//        // Save the log entry
//        UserAudit userAudit = new UserAudit();
//        userAudit.setUserAgent(userAgent);
//        userAudit.setIp(ip);
//        userAudit.setRequestMethod(requestMethod);
//        userAudit.setUrl(url);
//        userAudit.setChangeTime(LocalDateTime.now());
//        // Persist the user audit log
//        userAuditRepository.save(userAudit);
//    }
//
//}
