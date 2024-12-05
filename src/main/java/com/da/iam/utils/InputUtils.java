package com.da.iam.utils;

import com.da.iam.dto.request.BasedRequest;
import com.da.iam.dto.request.RegisterRequest;
import com.da.iam.service.PasswordService;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class InputUtils {
    //private static final UserService userService;
    private static PasswordService passwordService;
    public static final String EMAIL_PATTERN = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,30}$";
    public static final String PASSWORD_PATTERN = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$";
    public static final String PHONE_NUMBER_PATTERN = "^\\+?[0-9]{11}$";
    public static final String DOB_PATTERN = "^\\d{4}-\\d{2}-\\d{2}$";

}
