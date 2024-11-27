package com.da.iam.dto;

import com.da.iam.entity.Role;
import com.da.iam.entity.User;
import lombok.*;

import java.time.LocalDate;
import java.util.Set;


@Data
public class UserDto {
    private User user;
    public UserDto(User user){
        this.user = user;
    }
    Set<Role> roles;
}
