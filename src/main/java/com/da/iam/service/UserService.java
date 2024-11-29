package com.da.iam.service;

import com.da.iam.dto.UserProfile;
import com.da.iam.entity.User;
import com.da.iam.exception.UserNotFoundException;
import com.da.iam.repo.UserRepo;
import com.da.iam.utils.InputUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.Optional;
import java.util.UUID;

@RequiredArgsConstructor
@Service
public class UserService {
    private final UserRepo userRepo;

    public User getUserById(UUID id) {
        return userRepo.findById(id).orElseThrow(() -> new UserNotFoundException("User not found"));
    }

    //.orElseThrow(() -> new UserNotFoundException("User not found by getUserByEmail() in UserService"))
    public Optional<User> getUserByEmail(String email) {
        return userRepo.findByEmail(email);
    }

    public Iterable<User> getUsers() {
        return userRepo.findAll();
    }

    public User createUser(User user) {
        return userRepo.save(user);
    }

    public User updateUser(UserProfile userProfile) {
        if (!InputUtils.isValidPhoneNumber(userProfile.getPhone())) {
            throw new IllegalArgumentException("Invalid phone number");
        }
        if (!InputUtils.isValidDOB(userProfile.getDob())) {
            throw new IllegalArgumentException("Invalid date of birth");
        }
        User user = userRepo.findByEmail(userProfile.getEmail()).orElseThrow(() -> new UserNotFoundException("User not found"));
        user.setDob(LocalDate.parse(userProfile.getDob()));
        user.setPhone(userProfile.getPhone());
        return userRepo.save(user);
    }

    public void saveUser(User user) { userRepo.save(user);}

    public void deleteUser(UUID id) {userRepo.deleteById(id);}

}
