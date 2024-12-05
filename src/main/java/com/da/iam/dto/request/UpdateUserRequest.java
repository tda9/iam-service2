package com.da.iam.dto.request;

import com.da.iam.utils.InputUtils;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Past;
import jakarta.validation.constraints.Pattern;
import org.springframework.format.annotation.DateTimeFormat;

import java.time.LocalDate;
import java.util.Set;

public record UpdateUserRequest(
        @NotEmpty
        String userId,
        @Pattern(regexp = InputUtils.EMAIL_PATTERN, message = "Invalid email format")
        String email,
        @NotNull(message = "username cannot be null")
        String username,
        @NotNull(message = "firstName cannot be null")
        String firstName,
        @NotNull(message = "lastName cannot be null")
        String lastName,
        @DateTimeFormat(pattern = InputUtils.DOB_PATTERN)
        @Past(message = "Date of birth must be in the past")
        LocalDate dob,
        @Pattern(regexp = InputUtils.PHONE_NUMBER_PATTERN, message = "Invalid phone number format")
        String phone,

        @NotNull(message = "isVerified can not be null")
        Boolean isVerified,
        @NotNull(message = "isLock can not be null")
        Boolean isLock,
        @NotNull(message = "role cannot be null")
        Set<String> role,
        @NotNull(message = "deleted can not be null")
        Boolean deleted
) {}
