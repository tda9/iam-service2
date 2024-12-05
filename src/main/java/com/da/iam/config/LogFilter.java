package com.da.iam.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingResponseWrapper;

import java.io.CharArrayWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class LogFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        log.info("------------------------------- Request start -------------------------------");
        log.info("User-Agent: {}", request.getHeader("User-Agent"));
        log.info("Remote address: {}", request.getRemoteAddr());
        log.info("Method: {}", request.getMethod());
        log.info("URL: {}", request.getRequestURL());
        ContentCachingResponseWrapper responseWrapper = new ContentCachingResponseWrapper(response);

        try {
            filterChain.doFilter(request, responseWrapper); // Process request and response
        } finally {
            // Log the response body
            logResponse(responseWrapper);
            responseWrapper.copyBodyToResponse(); // Ensure response is sent to the client
        }
        filterChain.doFilter(request, response);
    }
    private void logResponse(ContentCachingResponseWrapper responseWrapper) {
        byte[] responseContent = responseWrapper.getContentAsByteArray();
        if (responseContent.length > 0) {
            String responseBody = new String(responseContent, StandardCharsets.UTF_8);
            log.info("Response Body: {}", responseBody);
        } else {
            log.info("Response Body is empty.");
        }
        log.info("Response Status: {}", responseWrapper.getStatus());
        log.info("------------------------------- Request end -------------------------------");
    }
//    private String getHeaders(HttpServletRequest request) {
//        var headers = new StringBuilder();
//        var headerNames = request.getHeaderNames();
//        while (headerNames.hasMoreElements()) {
//            String name = headerNames.nextElement();
//            headers.append(name).append(": ").append(request.getHeader(name)).append("\n");
//        }
//        return headers.toString();
//    }
//    private static class CharResponseWrapper extends HttpServletResponseWrapper {
//        private final CharArrayWriter charArrayWriter = new CharArrayWriter();
//        private final PrintWriter writer = new PrintWriter(charArrayWriter);
//
//        public CharResponseWrapper(HttpServletResponse response) {
//            super(response);
//        }

//        @Override
//        public PrintWriter getWriter() {
//            return writer;
//        }
//
//        @Override
//        public String toString() {
//            writer.flush();
//            return charArrayWriter.toString();
//        }
//
//        public String getHeaders() {
//            return super.getHeaderNames().stream()
//                    .map(name -> name + ": " + super.getHeader(name))
//                    .reduce("", (a, b) -> a + "\n" + b);
//        }
//    }
}
