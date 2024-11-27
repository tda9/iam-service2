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
    private RuntimeException exception;

    public BasedResponse<T> fail(String message, RuntimeException ex){
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

}
