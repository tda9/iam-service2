package com.da.iam.service.impl;

import com.da.iam.dto.request.CreateUserRequest;
import com.da.iam.dto.request.UpdateUserRequest;
import com.da.iam.dto.response.BasedResponse;
import com.da.iam.entity.User;
import com.da.iam.exception.ErrorResponseException;
import com.da.iam.repo.RoleRepo;
import com.da.iam.repo.UserRepo;
import com.da.iam.repo.UserRoleRepo;
import com.da.iam.service.BaseService;
import com.da.iam.service.BaseUserService;
import com.da.iam.service.EmailService;
import com.da.iam.service.PasswordService;
import com.da.iam.service.impl.KeycloakAuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@Service
public class KeycloakUserService extends BaseService implements BaseUserService {
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final UserRoleRepo userRoleRepo;
    private final PasswordService passwordService;
    private final KeycloakAuthenticationService keycloakAuthenticationService;
    private final UserService userService;

    public KeycloakUserService(UserRepo userRepo, RoleRepo roleRepo, PasswordEncoder passwordEncoder, EmailService emailService, UserRoleRepo userRoleRepo, PasswordService passwordService, KeycloakAuthenticationService keycloakAuthenticationService, UserService userService) {
        super(userRepo, roleRepo);
        this.passwordEncoder = passwordEncoder;
        this.emailService = emailService;
        this.userRoleRepo = userRoleRepo;
        this.passwordService = passwordService;
        this.keycloakAuthenticationService = keycloakAuthenticationService;
        this.userService = userService;
    }

    @Override
    public User create(CreateUserRequest request) {
        String email = request.email();
        LocalDate dob = request.dob();
        String image = request.image();
        String phone = request.phone();
        String username = request.username();
        String lastName = request.firstName();
        String firstName = request.firstName();
        checkEmailExisted(email);
        List<UUID> rolesId = getRoles(request.role());//check hop le cac role co trong db ko va tra ve list id cua cac role
        String generatedPassword = passwordService.generateToken();
        emailService.sendEmail(email, "Your IAM Service Password", generatedPassword);//gui mat khau cho user
        User newUser = User.builder()
                .dob(dob)
                .image(image)
                .phone(phone)
                .email(email)
                .username(username)
                .firstName(firstName)
                .lastName(lastName)
                .password(passwordEncoder.encode(generatedPassword))
                .build();//khoi tao user
        try {
            User user = userRepo.save(newUser);//save user
            rolesId.forEach(roleId -> userRoleRepo.saveUserRole(user.getUserId(), roleId));
//          emailService.sendConfirmationRegistrationEmail(request.email(), tokenResponse.getAccessToken());
            keycloakAuthenticationService.createKeycloakUser(email,generatedPassword);
            return user;
        } catch (Exception e) {
            throw new ErrorResponseException("Create failed: " + e.getMessage());
        }
    }

    @Override
    @Transactional
    public User updateById(UpdateUserRequest request) {

        String oldEmail = userRepo.findById(UUID.fromString(request.userId())).orElseThrow().getEmail();
        keycloakAuthenticationService.updateKeycloakUser(request,oldEmail);
        return userService.updateById(request);
    }


}
