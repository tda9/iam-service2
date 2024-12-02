package com.da.iam.service;

import com.da.iam.dto.UserProfile;
import com.da.iam.dto.request.CreateUserRequest;
import com.da.iam.dto.request.UpdateUserRequest;
import com.da.iam.dto.response.BasedResponse;
import com.da.iam.entity.User;
import com.da.iam.exception.UserNotFoundException;
import com.da.iam.repo.*;
import com.da.iam.utils.InputUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.repository.query.Param;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.*;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@Service
public class UserService implements BaseUserService {

    private final UserRepo userRepo;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final RoleRepo roleRepo;
    private final UserRoleRepo userRoleRepo;
    private final PasswordService passwordService;
    //private final KeycloakAuthenticationService keycloakAuthenticationService;

    public User getUserById(UUID id) {
        return userRepo.findById(id).orElseThrow(() -> new UserNotFoundException("User not found"));
    }

    //.orElseThrow(() -> new UserNotFoundException("User not found by getUserByEmail() in UserService"))
//    public Optional<User> getUserByEmail(String email) {
//        return userRepo.findByEmail(email);
//    }

    public Iterable<User> getUsers() {
        return userRepo.findAll();
    }

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

        emailService.sendEmail(email, "Your IAM Service Password", generatedPassword);//gui mat khau cho user
        User newUser = User.builder()
                .dob(dob)
                .image(image)
                .phone(phone)
                .email(email)
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

            //keycloakAuthenticationService.createKeycloakUser(email,generatedPassword);

            return new BasedResponse().success("Create successful", newUser);
        } catch (Exception e) {
            throw new IllegalArgumentException("Create failed: " + e.getMessage());
        }
    }

    @Override
    @Transactional
    public BasedResponse<?> updateById(UpdateUserRequest request) {
        UUID id = UUID.fromString(request.userId());
        String email = request.email();
        String image = request.image();
        LocalDate dob = request.dob();
        String phone = request.phone();
        boolean delete = request.deleted();
        boolean isVerified = request.isVerified();
        boolean isLock = request.isLock();
        List<UUID> roles = getRoles(request.role());
        User user = userRepo.findById(id).orElseThrow(() -> new UserNotFoundException("User not found"));
        if (userRepo.existsByEmailAndUserIdNot(email, id)) {//kiem tra co trung permission khac ko
            throw new IllegalArgumentException("Email existed");
        }
        try {
            user.setDob(dob);
            user.setEmail(email);
            user.setPhone(phone);
            user.setLock(isLock);
            user.setImage(image);
            user.setDeleted(delete);
            user.setVerified(isVerified);
            userRepo.save(user);
            isOperationSuccess(userRoleRepo.deleteByUserId(user.getUserId()),"Update failed");
            addRolesToUser(user.getUserId(),roles);
            return new BasedResponse().success("Update successful", userRepo.findById(user.getUserId()));
        } catch (Exception ex) {
            throw new IllegalArgumentException("Update user failed");
        }
    }


    public void save(User user) {
        userRepo.save(user);
    }

    private List<UUID> getRoles(Set<String> requestRoles) {
        return requestRoles.stream().map(String::trim)
                .map(roleRepo::findRoleIdByName)
                .peek(role -> {
                    if (role.isEmpty() || roleRepo.findById(role.get()).get().isDeleted()) {
                        throw new IllegalArgumentException("Role not found or was deleted");
                    }
                })
                .map(Optional::get)
                .toList()
                ;
    }

    private void isOperationSuccess(int isSuccess, String message) {
        if (isSuccess == 0) {
            throw new IllegalArgumentException(message);
        }
    }

    @Transactional
    public void addRolesToUser(UUID userId, List<UUID> roleIds) {
        for (UUID roleId : roleIds) {
            userRoleRepo.insertUserRoles(userId,roleId);
        }
    }

    public boolean userHasPermission(Authentication currentUser,Object target, Object requiredPermission ){
        List<GrantedAuthority> authorities = new ArrayList<>(currentUser.getAuthorities());

        // Ensure the requiredPermission is a String
        if (!(requiredPermission instanceof String)) {
            throw new IllegalArgumentException("Required permission must be a string.");
        }

        String requiredAction = (String) requiredPermission;

        // Check user's roles or permissions against the required action
        for (GrantedAuthority authority : authorities) {
            if (authority.getAuthority().equals(requiredAction)) {
                return true; // User has the required permission
            }
        }

        return false;
    }
}
