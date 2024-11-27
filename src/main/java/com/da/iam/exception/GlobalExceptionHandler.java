package com.da.iam.exception;


import com.da.iam.dto.response.BasedResponse;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<BasedResponse<?>> handleIllegalArgumentException(IllegalArgumentException ex) {
        return ResponseEntity.status(400).body(BasedResponse.builder()
                .requestStatus(false)
                .httpStatusCode(400)
                .message(ex.getMessage())
                .exception(ex)
                .build());
    }

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<BasedResponse<?>> handleUserNotFoundException(UserNotFoundException ex) {
        return ResponseEntity.status(400).body(BasedResponse.builder()
                .requestStatus(false)
                .httpStatusCode(400)
                .message(ex.getMessage())
                .exception(ex)
                .build());
    }

    @ExceptionHandler(ErrorResponseException.class)
    public ResponseEntity<?> handleErrorResponseException(ErrorResponseException ex) {
        return ResponseEntity.status(400).body(BasedResponse.builder()
                .requestStatus(false)
                .httpStatusCode(400)
                .message(ex.getMessage())
                .exception(ex)
                .build());
    }

}
