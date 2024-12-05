package com.da.iam.dto.response;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import lombok.*;
import org.springframework.http.HttpHeaders;

import java.io.Serializable;
import java.time.Instant;

@EqualsAndHashCode(callSuper = false)
@AllArgsConstructor
@Data
@Builder

public class BasedResponse<T> implements Serializable {
    private boolean requestStatus;
    private int httpStatusCode;
    @Builder.Default
    private long timestamp = Instant.now().toEpochMilli();

    private String message;
    private T data;

    @JsonIgnore
    private Exception exception;

    public BasedResponse(){
        this.timestamp = Instant.now().toEpochMilli();
    }
    public static <T> BasedResponse<T> fail(String message, Exception ex){
        BasedResponse<T> response = new BasedResponse<>();
        response.setException(ex);
        response.setHttpStatusCode(400);
        response.setMessage(message);
        response.setRequestStatus(false);
        return response;
    }

    public static<T> BasedResponse<T> success(String message, T data){
        BasedResponse<T> response = new BasedResponse<>();
        response.setHttpStatusCode(200);
        response.setMessage(message);
        response.setRequestStatus(true);
        response.setData(data);
        return response;
    }
    public static<T> BasedResponse<T> created(String message, T data){
        BasedResponse<T> response = new BasedResponse<>();
        response.setRequestStatus(true);
        response.setHttpStatusCode(201);
        response.setMessage(message);
        response.setRequestStatus(true);
        response.setData(data);
        return response;
    }
    public BasedResponse<T> badRequest(String message){
        this.setRequestStatus(false);
        this.setHttpStatusCode(400);
        this.setMessage(message);
        return this;
    }

}
