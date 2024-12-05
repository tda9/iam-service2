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
        @NotEmpty(message = "Email cannot be empty")
        @Pattern(regexp = InputUtils.EMAIL_PATTERN, message = "Invalid email format")
        String email,
        @DateTimeFormat(pattern = InputUtils.DOB_PATTERN)
        @Past(message = "Date of birth must be in the past")
        LocalDate dob,
        @Pattern(regexp = InputUtils.PHONE_NUMBER_PATTERN, message = "Invalid phone number format")
        String phone,
        @NotNull(message = "username cannot be null")
        @Pattern(regexp = "^[a-zA-Z0-9._-]{3,}$", message = "Username must contain letters or digits with minimum 3 character")
        String username,
        @NotNull(message = "firstName cannot be null")
        @Pattern(regexp = "^[a-zA-Z0-9_-]{3,}$", message = "First name must contain letters or digits with minimum 3 character")
        String firstName,
        @NotNull(message = "lastName cannot be null")
        @Pattern(regexp = "^[a-zA-Z0-9_-]{3,}$", message = "Last name must contain letters or digits with minimum 3 character")
        String lastName,
        @NotNull(message = "Roles cannot be null")
        Set<String> role) {
        //Default:
        //deleted: false, isVerified: false, isLock: false
}
