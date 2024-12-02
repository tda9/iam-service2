package com.da.iam.dto.request;

import com.da.iam.entity.Role;
import com.da.iam.utils.InputUtils;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.util.Set;


@Builder
public record RegisterRequest(
        @Pattern(regexp = InputUtils.EMAIL_PATTERN, message = "Invalid email format")
        String email,
        @Pattern(regexp = InputUtils.PASSWORD_PATTERN, message = "Invalid password format")
        String password,
        @Pattern(regexp = InputUtils.DOB_PATTERN, message = "Invalid date of birth format")
        LocalDate dob,
        @Pattern(regexp = InputUtils.PHONE_NUMBER_PATTERN, message = "Invalid phone number format")
        String phone,
        Set<String> role) {
}
