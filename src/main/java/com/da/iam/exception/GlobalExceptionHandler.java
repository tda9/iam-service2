package com.da.iam.exception;


import com.da.iam.dto.response.BasedResponse;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import jakarta.validation.UnexpectedTypeException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;
import java.util.Objects;

@Slf4j
@ControllerAdvice
public class GlobalExceptionHandler {

    //AuthorizationDeniedException bo sung them
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<BasedResponse<?>> handleIllegalArgumentException(IllegalArgumentException ex) {
        log.error(ex.getMessage());
        return ResponseEntity.status(400).body(BasedResponse.fail(ex.getMessage(), ex));
    }
    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<BasedResponse<?>> handleUserNotFoundException(UserNotFoundException ex) {
        log.error(ex.getMessage());
        return ResponseEntity.status(400).body(BasedResponse.fail(ex.getMessage(),ex));
    }
    @ExceptionHandler(ErrorResponseException.class)
    public ResponseEntity<?> handleErrorResponseException(ErrorResponseException ex) {
        log.error(ex.getMessage());
        return ResponseEntity.status(400).body(BasedResponse.fail(ex.getMessage(), ex));
    }
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<?> handleValidationExceptions(MethodArgumentNotValidException ex) {
        StringBuilder errorMessages = new StringBuilder();
        for (FieldError error : ex.getBindingResult().getFieldErrors()) {
            errorMessages.append(error.getField()).append(": ").append(error.getDefaultMessage()).append("\n");
        }
        log.error(ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(BasedResponse.fail(errorMessages.toString(),ex));
    }
    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<?> handleConstraintViolationExceptions(ConstraintViolationException ex) {
        StringBuilder errorMessages = new StringBuilder();
        for (ConstraintViolation<?> violation : ex.getConstraintViolations()) {
            errorMessages.append(violation.getPropertyPath()).append(": ").append(violation.getMessage()).append("\n");
        }
        log.error(ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(BasedResponse.fail(errorMessages.toString(), ex));
    }
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<?> handleErrorResponseException(HttpMessageNotReadableException ex) {
        log.error(ex.getMessage());
        return ResponseEntity.status(400).body(BasedResponse.fail(ex.getMessage(), null));
    }
    @ExceptionHandler(UnexpectedTypeException.class)
    public ResponseEntity<?> handleWrongTypeException(UnexpectedTypeException ex) {
        log.error(ex.getMessage());
        return ResponseEntity.status(400).body(BasedResponse.fail(ex.getMessage(), ex));
    }
    @ExceptionHandler(NullPointerException.class)
    public ResponseEntity<?> handleNullException(NullPointerException ex) {
        log.error(ex.getMessage());
        return ResponseEntity.status(400).body(BasedResponse.fail(ex.getMessage(), ex));
    }

}
