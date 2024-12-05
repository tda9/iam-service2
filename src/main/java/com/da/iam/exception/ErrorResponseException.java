package com.da.iam.exception;

public class ErrorResponseException extends RuntimeException{
    public ErrorResponseException(String msg){
        super(msg);
    }
}
