package com.da.iam.service;

import com.da.iam.dto.request.CreateUserRequest;
import com.da.iam.dto.request.UpdateUserRequest;
import com.da.iam.dto.response.BasedResponse;
import com.da.iam.entity.User;
import com.da.iam.repo.RoleRepo;
import com.da.iam.repo.UserRepo;
import com.da.iam.repo.UserRoleRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
@RequiredArgsConstructor
@Service
public class KeycloakUserService implements BaseUserService{
    private final UserRepo userRepo;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final RoleRepo roleRepo;
    private final UserRoleRepo userRoleRepo;
    private final PasswordService passwordService;
    private final KeycloakAuthenticationService keycloakAuthenticationService;
    @Override
    public BasedResponse<?> create(CreateUserRequest request) {
        String email = request.email();
        LocalDate dob = request.dob();
        String image = request.image();
        String phone = request.phone();
        if (userRepo.existsByEmail(email)) {
            return new BasedResponse().badRequest("Email existed");
        }
        List<UUID> rolesId = getRoles(request.role());//check hop le cac role co trong db ko va tra ve list id cua cac role
        String generatedPassword = passwordService.generateToken();

        emailService.sendEmail(email,"Your IAM Service Password",generatedPassword);//gui mat khau cho user
        User newUser = User.builder()
                .email(email)
                .phone(phone)
                .image(image)
                .dob(dob)
                .password(passwordEncoder.encode(generatedPassword))
                .build();//khoi tao user

        try {
            userRepo.save(newUser);//save user
            rolesId.forEach(roleId -> userRoleRepo.saveUserRole(userRepo.getUserIdByEmail(email).orElseThrow(() -> {
                throw new IllegalArgumentException("Error during save user id to user_role table");
            }), roleId));//save role cua user
//            var jwtToken = jwtService.generateToken(email);
//            var jwtRefreshToken = jwtService.generateRefreshToken(email);
//            DefaultTokenResponse tokenResponse = new DefaultTokenResponse(jwtToken, jwtRefreshToken, "Bearer");
            ////5 phut hieu luc, trong thoi gian do khong duoc gui them
//          emailService.sendConfirmationRegistrationEmail(request.email(), tokenResponse.getAccessToken());
//          authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, password));

            keycloakAuthenticationService.createKeycloakUser(email,generatedPassword);

            return new BasedResponse().success("Create successful", newUser);
        } catch (Exception e) {
            throw new IllegalArgumentException("Create failed: " + e.getMessage());
        }
    }

    @Override
    public BasedResponse<?> updateById(UpdateUserRequest request) {
        return null;
    }

    private List<UUID> getRoles(Set<String> requestRoles) {
        return requestRoles.stream().map(String::trim)
                .map(roleRepo::findRoleIdByName)
                .peek(role -> {
                    if(role.isEmpty()|| roleRepo.findById(role.get()).get().isDeleted()){
                        throw new IllegalArgumentException("Role not found or was deleted");
                    }
                })
                .map(Optional::get)
                .toList()
                ;
    }
}
