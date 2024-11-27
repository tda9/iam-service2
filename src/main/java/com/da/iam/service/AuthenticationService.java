package com.da.iam.service;

import com.da.iam.dto.request.LoginRequest;
import com.da.iam.dto.request.RegisterRequest;
import com.da.iam.dto.response.BasedResponse;
import com.da.iam.entity.*;
import com.da.iam.exception.TooManyRequestsException;
import com.da.iam.exception.UserNotFoundException;
import com.da.iam.repo.*;


import com.da.iam.utils.InputUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final JWTService jwtService;
    private final UserRepo userRepo;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final EmailService emailService;
    private final RoleRepo roleRepo;
    private final UserRoleRepo userRoleRepo;
    private final PasswordService passwordService;
    private final PasswordResetTokenRepo passwordResetTokenRepo;
    private final BlackListTokenRepo blackListTokenRepo;
    private final UserService userService;
    @Value("${application.security.jwt.enable}")
    private boolean iamJwtEnabled;
    public BasedResponse<?> register(RegisterRequest request) {
        //check null request, null/empty email, password
        InputUtils.isValidRegisterRequest(request);
        String email = request.email();
        String password = request.password();
        //check email ton tai
        if (userService.getUserByEmail(request.email()).isPresent()) {
            throw new IllegalArgumentException("Email existed");
        }

        User userEntity = User.builder().email(email).password(passwordEncoder.encode(password)).build();

        //save user to user table
        userService.saveUser(userEntity);
//        for (Role r : roles) {
//            //Role role = roleRepo.findRoleByName(r.getName());
//            Role role = roleRepo.findRoleByName("USER");
//            UserRoles userRoles = new UserRoles(userEntity.getUserId(), role.getRoleId());
//            userRoleRepo.saveUserRole(userEntity.getUserId(), userRoles.getRoleId());
//        }
//        Set<Role> roles = getRoles(request.role());
        Role role = roleRepo.findRoleByName("USER");
        UserRoles userRoles = new UserRoles(userEntity.getUserId(), role.getRoleId());

        //save all user's roles to db
        userRoleRepo.saveUserRole(userEntity.getUserId(), userRoles.getRoleId());


        //DEACTIVATE: send email confirm registration here
        //String token = passwordService.generateToken();
        //5 phut hieu luc, trong thoi gian do khong duoc gui them
        //sendConfirmation(request.email(), token, userEntity);
        if(iamJwtEnabled) {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, password));
            var jwtToken = jwtService.generateToken(userEntity.getEmail());
            blackListTokenRepo.save(new BlackListToken(jwtToken, LocalDateTime.now().plusMinutes(10), userEntity.getUserId()));
            return BasedResponse.builder()
                    .httpStatusCode(200)
                    .requestStatus(true)
                    .data(jwtToken)
                    .build();
        }
        return BasedResponse.builder()
                .httpStatusCode(200)
                .requestStatus(true)
                .message("We send confirmation register to your email. It will expire in 5 minutes")
                .data(userEntity)
                .build();
    }

    //    public void sendConfirmation(String to, String token, User userEntity) {
//        if (userEntity == null) {
//            throw new UserNotFoundException("User Entity null");
//        }
//        Optional<PasswordResetToken> lastToken = passwordResetTokenRepo.findTopByUserIdOrderByCreatedAtDesc(userEntity.getUserId());
//        if (lastToken.isPresent() && lastToken.get().getExpirationDate().isBefore(LocalDateTime.now())) {
//            throw new TooManyRequestsException("You can only request a password reset every 5 minutes.");
//        } else if (lastToken.isPresent() && lastToken.get().getExpirationDate().isAfter(LocalDateTime.now())) {
//            passwordResetTokenRepo.delete(lastToken.get());
//        }
//        emailService.sendConfirmationRegistrationEmail(to, token);
//        passwordResetTokenRepo.save(new PasswordResetToken(token, LocalDateTime.now().plusMinutes(5), userEntity.getUserId()));
//    }
//
//    public void confirmEmail(String email, String token) {
//        User user = userRepo.findByEmail(email).orElseThrow(() -> new UserNotFoundException("User not found"));
//        PasswordResetToken requestToken = passwordResetTokenRepo.findPasswordResetTokenByToken(token);
//        if (requestToken.getExpirationDate().isBefore(LocalDateTime.now()) || !Objects.equals(user.getUserId(), requestToken.getUserId())) {
//            throw new IllegalArgumentException("Invalid or expired token");
//        }
//        user.setConfirm(true);
//        userRepo.save(user);
//        passwordResetTokenRepo.delete(requestToken);
//    }
//
    public BasedResponse<?> authenticate(LoginRequest request) {
        String email = request.email();
        String password = request.password();

        User userEntity = userRepo.findByEmail(request.email()).orElseThrow(() -> new UserNotFoundException("User not found"));

//        if (!userEntity.isVerified()) {
//            String token = passwordService.generateToken();
//            sendConfirmation(request.email(), token, userEntity);
//            return BasedResponse.builder()
//                    .httpStatusCode(400)
//                    .requestStatus(false)
//                    .data(email)
//                    .message("Email hasn't been confirmed. We send confirmation register to your email. It will expire in 5 minutes")
//                    .build();
//        }
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, password));
        //var jwtToken = jwtService.generateToken(userEntity.getEmail());
        //blackListTokenRepo.save(new BlackListToken(jwtToken, LocalDateTime.now().plusMinutes(10), LocalDateTime.now(), userEntity.getUserId()));
        return BasedResponse.builder()
                .httpStatusCode(200)
                .requestStatus(true)
                //.data(jwtToken)
                .build();
    }
//
//    private Set<Role> getRoles(Set<String> roles) {
//        Set<Role> rolesSet = new HashSet<>();
//        for (String role : roles) {
//            Role tmpRole = new Role();
//            tmpRole.setName(role);
//            rolesSet.add(tmpRole);
//        }
//        return rolesSet;
//    }
//
//    @Transactional//tim hieu tai sao o day can transactional
//    public void logout(String email) {
//        User u = userRepo.findByEmail(email).orElseThrow();
//        blackListTokenRepo.deleteAllByUserId(u.getUserId());
//    }
}
