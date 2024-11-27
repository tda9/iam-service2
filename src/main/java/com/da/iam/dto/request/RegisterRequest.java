package com.da.iam.dto.request;

import com.da.iam.entity.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.util.Set;


@Builder
public record RegisterRequest(String email, String password, LocalDate dob, String phone) {
    //,Set<String> role
}
