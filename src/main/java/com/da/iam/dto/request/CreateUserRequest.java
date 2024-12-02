package com.da.iam.dto.request;

import com.da.iam.utils.InputUtils;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Past;
import jakarta.validation.constraints.Pattern;
import org.springframework.format.annotation.DateTimeFormat;

import java.time.LocalDate;
import java.util.Set;

public record CreateUserRequest(
        @NotEmpty
        @Pattern(regexp = InputUtils.EMAIL_PATTERN, message = "Invalid email format")
        String email,
        //@Pattern(regexp = InputUtils.DOB_PATTERN, message = "Invalid date of birth format")
        @DateTimeFormat(pattern = "yyyy-MM-dd")
        @Past(message = "Date of birth must be in the past")
        LocalDate dob,
        @Pattern(regexp = InputUtils.PHONE_NUMBER_PATTERN, message = "Invalid phone number format")
        String phone,
        @NotNull
        String image,
        @NotNull(message = "role cannot be null")
        Set<String> role) {

}
