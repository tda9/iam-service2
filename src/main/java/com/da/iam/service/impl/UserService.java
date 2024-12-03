package com.da.iam.service.impl;

import com.da.iam.dto.request.CreateUserRequest;
import com.da.iam.dto.request.SearchUserRequest;
import com.da.iam.dto.request.UpdateUserRequest;
import com.da.iam.dto.response.BasedResponse;
import com.da.iam.entity.User;
import com.da.iam.exception.ErrorResponseException;
import com.da.iam.exception.UserNotFoundException;
import com.da.iam.repo.RoleRepo;
import com.da.iam.repo.UserRepo;
import com.da.iam.repo.UserRoleRepo;
import com.da.iam.service.BaseService;
import com.da.iam.service.BaseUserService;
import com.da.iam.service.EmailService;
import com.da.iam.service.PasswordService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

@Slf4j
@Service
public class UserService extends BaseService implements BaseUserService {
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final UserRoleRepo userRoleRepo;
    private final PasswordService passwordService;

    public UserService(UserRepo userRepo, RoleRepo roleRepo, PasswordEncoder passwordEncoder, EmailService emailService, UserRoleRepo userRoleRepo, PasswordService passwordService) {
        super(userRepo, roleRepo);
        this.passwordEncoder = passwordEncoder;
        this.emailService = emailService;
        this.userRoleRepo = userRoleRepo;
        this.passwordService = passwordService;
    }

    public Page<User> searchByKeyword(SearchUserRequest request, int currentPage, int currentSize, String sortBy, String sort) {
        Pageable pageable = PageRequest.of(currentPage, currentSize, Sort.by(
                Sort.Order.by(sortBy).with(Sort.Direction.fromString(sort))
        ));
        String keyword = "%"+request.keyword()+"%";
        return userRepo.searchByKeyword(keyword, pageable);
    }

    private boolean isValidColumnName(String columnName) {
        // Implement a method to validate if the column name is safe (e.g., check against a whitelist of columns)
        List<String> validColumns = Arrays.asList(
                "email",
                "firstName",
                "lastName",
                "username");
        return validColumns.contains(columnName);
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
            User user = userRepo.save(newUser);
            rolesId.forEach(roleId -> userRoleRepo.saveUserRole(user.getUserId(), roleId));
//          emailService.sendConfirmationRegistrationEmail(request.email(), tokenResponse.getAccessToken());
            return user;
        } catch (Exception e) {
            throw new ErrorResponseException("Create failed: " + e.getMessage());
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
            isOperationSuccess(userRoleRepo.deleteByUserId(user.getUserId()), "Update failed");
            addRolesToUser(user.getUserId(), roles);
            return new BasedResponse().success("Update successful", userRepo.findById(user.getUserId()));
        } catch (Exception ex) {
            throw new IllegalArgumentException("Update user failed");
        }
    }

    public void save(User user) {
        userRepo.save(user);
    }

    private void isOperationSuccess(int isSuccess, String message) {
        if (isSuccess == 0) {
            log.error("Error at isOperationSuccess");
            throw new IllegalArgumentException(message);
        }
    }

    @Transactional
    public void addRolesToUser(UUID userId, List<UUID> roleIds) {
        for (UUID roleId : roleIds) {
            userRoleRepo.insertUserRoles(userId, roleId);
        }
    }

    public boolean userHasPermission(Authentication currentUser, Object target, Object requiredPermission) {
        List<GrantedAuthority> authorities = new ArrayList<>(currentUser.getAuthorities());
        log.info("USER GRANT----------SYSTEM" + String.valueOf(target) + "." + String.valueOf(requiredPermission));
        for (GrantedAuthority authority : authorities) {
            log.info(authority + "---" + String.valueOf(target) + "." + String.valueOf(requiredPermission));
            if (authority.getAuthority().equals(String.valueOf(target) + "." + String.valueOf(requiredPermission))) {
                return true;
            }
        }
        return false;
    }
}
