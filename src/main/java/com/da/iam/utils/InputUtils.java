package com.da.iam.utils;

import com.da.iam.dto.request.RegisterRequest;
import com.da.iam.service.PasswordService;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class InputUtils {
    //private static final UserService userService;
private static PasswordService passwordService;
    public static final String EMAIL_PATTERN = "^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$";

    public static void  isValidEmail(String email) {
        if (email == null || email.isEmpty()) {
            throw new IllegalArgumentException("Missing request email");
        }
        //else if (!email.matches(EMAIL_PATTERN)) {
//            throw new IllegalArgumentException("Invalid email format");
//        }
    }

    public static boolean isValidPhoneNumber(String phoneNumber) {
        return phoneNumber.matches("^\\+?[0-9]{11}$");
    }

    public static boolean isValidDOB(String dob) {
        return dob.matches("^\\d{4}-\\d{2}-\\d{2}$");
    }

    public static void isValidRegisterRequest(RegisterRequest request) {
        if(request==null){
            throw new IllegalArgumentException("Missing request body");
        }
        String email = request.email();
        String password = request.password();
        InputUtils.isValidEmail(email);
        if (password == null || password.isEmpty()) {
            throw new IllegalArgumentException("Missing request password");
        }
    }


}