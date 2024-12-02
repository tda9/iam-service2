package com.da.iam.exception;

public class SaveToDatabaseFailedException extends RuntimeException {
    public SaveToDatabaseFailedException(String message) {
        super(message);
    }
}
