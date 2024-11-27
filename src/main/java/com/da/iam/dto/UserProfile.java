package com.da.iam.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@Data
public class UserProfile {
    private String email;
    private String dob;
    private String phone;
    private String image;
}
