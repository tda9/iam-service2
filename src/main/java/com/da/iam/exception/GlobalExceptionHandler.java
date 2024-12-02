package com.da.iam.exception;


import com.da.iam.dto.response.BasedResponse;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import jakarta.validation.UnexpectedTypeException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    //AuthorizationDeniedException bo sung them
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
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<String> handleValidationExceptions(MethodArgumentNotValidException ex) {
        StringBuilder errorMessages = new StringBuilder();
        for (FieldError error : ex.getBindingResult().getFieldErrors()) {
            errorMessages.append(error.getField()).append(": ").append(error.getDefaultMessage()).append("\n");
        }
        return new ResponseEntity<>(errorMessages.toString(), HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<String> handleConstraintViolationExceptions(ConstraintViolationException ex) {
        StringBuilder errorMessages = new StringBuilder();
        for (ConstraintViolation<?> violation : ex.getConstraintViolations()) {
            errorMessages.append(violation.getPropertyPath()).append(": ").append(violation.getMessage()).append("\n");
        }
        return new ResponseEntity<>(errorMessages.toString(), HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<?> handleErrorResponseException(HttpMessageNotReadableException ex) {
        return ResponseEntity.status(400).body(BasedResponse.builder()
                .requestStatus(false)
                .httpStatusCode(400)
                .message(ex.getMessage())
                .exception(ex)
                .build());
    }
    @ExceptionHandler(NullPointerException.class)
    public ResponseEntity<?> handleNullException(NullPointerException ex) {
        return ResponseEntity.status(400).body(
                BasedResponse.builder()
                .requestStatus(false)
                .httpStatusCode(400)
                .message(ex.getMessage())
                .exception(ex)
                .build());
    }
    @ExceptionHandler(UnexpectedTypeException.class)
    public ResponseEntity<?> handleWrongTypeException(UnexpectedTypeException ex) {
        return ResponseEntity.status(400).body(BasedResponse.builder()
                .requestStatus(false)
                .httpStatusCode(400)
                .message(ex.getMessage())
                .exception(ex)
                .build());
    }

}
