package com.da.iam.dto.request;

import com.da.iam.entity.Role;
import com.da.iam.entity.User;
import lombok.*;

import java.time.LocalDate;
import java.util.Set;

@AllArgsConstructor
@Data
public class UserDto {
    private String email;
    private String password;
    private String phone;
    private LocalDate dob;
    private String image;
    Set<Role> roles;
}
