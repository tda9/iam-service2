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
@NoArgsConstructor
public class BasedResponse<T> implements Serializable {
    private boolean requestStatus;
    private int httpStatusCode;
    @Builder.Default
    private long timestamp = Instant.now().toEpochMilli();

    private String message;
    private T data;

    @JsonIgnore
    private Exception exception;

    public BasedResponse<T> fail(String message, Exception ex){
        this.setException(ex);
        this.setHttpStatusCode(400);
        this.setMessage(message);
        this.setRequestStatus(false);
        return this;
    }

    public BasedResponse<T> success(String message, T data){
        this.setHttpStatusCode(200);
        this.setMessage(message);
        this.setRequestStatus(true);
        this.setData(data);
        return this;
    }
    public BasedResponse<T> created(String message, T data){
        this.setRequestStatus(true);
        this.setHttpStatusCode(201);
        this.setMessage(message);
        this.setRequestStatus(true);
        this.setData(data);
        return this;
    }
    public BasedResponse<T> badRequest(String message){
        this.setRequestStatus(false);
        this.setHttpStatusCode(400);
        this.setMessage(message);
        return this;
    }

}
