package com.da.iam.service.impl;

import com.da.iam.dto.request.CreateUserRequest;
import com.da.iam.dto.request.UpdateUserRequest;
import com.da.iam.dto.response.DefaultTokenResponse;
import com.da.iam.entity.User;
import com.da.iam.exception.ErrorResponseException;
import com.da.iam.exception.UserNotFoundException;
import com.da.iam.repo.BlackListTokenRepo;
import com.da.iam.repo.RoleRepo;
import com.da.iam.repo.UserRepo;
import com.da.iam.repo.UserRoleRepo;
import com.da.iam.repo.impl.UserRepoImpl;
import com.da.iam.service.*;
import lombok.extern.slf4j.Slf4j;
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
    private final UserRepoImpl userRepoImpl;


    public UserService(UserRepo userRepo,
                       RoleRepo roleRepo,
                       PasswordEncoder passwordEncoder,
                       EmailService emailService,
                       UserRoleRepo userRoleRepo,
                       PasswordService passwordService,
                       UserRepoImpl userRepoImpl,
                       BlackListTokenRepo blackListTokenRepo,
                       JWTService jwtService) {
        super(userRepo, roleRepo, blackListTokenRepo,jwtService);
        this.passwordEncoder = passwordEncoder;
        this.emailService = emailService;
        this.userRoleRepo = userRoleRepo;
        this.passwordService = passwordService;
        this.userRepoImpl = userRepoImpl;
    }

//    public Page<User> searchByKeyword(String request, int currentPage, int currentSize, String sortBy, String sort) {
//        Pageable pageable = PageRequest.of(currentPage, currentSize, Sort.by(
//                Sort.Order.by(sortBy).with(Sort.Direction.fromString(sort))
//        ));
//        String keyword = "%" + request + "%";
//        return userRepo.searchByKeyword(keyword, pageable);
//    }

    private boolean isValidColumnName(String columnName) {
        // Implement a method to validate if the column name is safe
        List<String> validColumns = Arrays.asList(
                "email",
                "firstName",
                "lastName",
                "username");
        return validColumns.contains(columnName);
    }

    @Override
    public User create(CreateUserRequest request) {
        try {
        checkEmailExisted(request.email());
        List<UUID> rolesId = getRoles(request.role());//check hop le cac role co trong db ko va tra ve list id cua cac role
        String generatedPassword = passwordService.generateToken();
        emailService.sendEmail(request.email(), "Your IAM Service Password", generatedPassword);//gui mat khau cho user
        User newUser = User.builder()//khoi tao user,
                .dob(request.dob())
                .image(null)
                .phone(request.phone())
                .email(request.email())
                .username(request.username())
                .firstName(request.firstName())
                .lastName(request.lastName())
                .password(passwordEncoder.encode(generatedPassword))
                .build();
            User user = userRepo.save(newUser);
            rolesId.forEach(roleId -> userRoleRepo.saveUserRole(user.getUserId(), roleId));
            DefaultTokenResponse tokenResponse = generateDefaultToken(request.email(), user.getUserId());
            emailService.sendConfirmationRegistrationEmail(request.email(), tokenResponse.getAccessToken());
            return user;
        } catch (Exception e) {
            throw new ErrorResponseException("Create failed: " + e.getMessage());
        }
    }

    @Override
    @Transactional
    public User updateById(UpdateUserRequest request) {
        UUID id = UUID.fromString(request.userId());
        List<UUID> roles = getRoles(request.role());
        User user = userRepo.findById(id).orElseThrow(() -> new UserNotFoundException("User not found during update"));
        if (userRepo.existsByEmailAndUserIdNot(request.email(), id)) {//kiem tra co trung permission khac ko
            throw new IllegalArgumentException("Email existed");
        }
        try {
            user.setDob(request.dob());
            user.setEmail(request.email());
            user.setPhone(request.phone());
            user.setLock(request.isLock());
            user.setImage(null);
            user.setDeleted(request.deleted());
            user.setVerified(request.isVerified());
            user.setUsername(request.username());
            user.setFirstName(request.firstName());
            user.setLastName(request.lastName());
            User updatedUser = userRepo.save(user);
            addRolesToUser(user.getUserId(), roles);
            return updatedUser;
        } catch (Exception ex) {
            log.error("Error at class UserService, function updateById: {}", ex.getMessage());
            throw new ErrorResponseException("Update user failed");
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

    public List<User> searchByKeyword(String keyword, String sortBy,String sort,int currentSize,int currentPage) {
        return userRepoImpl.searchByKeyword(keyword,sortBy,sort,currentSize, currentPage);
    }
    public List<User> searchByField(String keyword) {
        List<User> user = userRepoImpl.searchByField(keyword);
        if(user == null || user.isEmpty()){
            throw new ErrorResponseException("No user found");
        }
        return user;
    }

    public User findById(String id){
        return userRepo.findById(UUID.fromString(id)).orElseThrow(()->new UserNotFoundException("User not found"));
    }
    public User findByEmail(String email){
        return userRepo.findByEmail(email).orElseThrow(()->new UserNotFoundException("User not found"));
    }
    public Long getTotalSize(String keyword) {
        return userRepoImpl.getTotalSize(keyword);
    }
    //isOperationSuccess(userRoleRepo.deleteByUserId(user.getUserId()), "Update failed");
}
