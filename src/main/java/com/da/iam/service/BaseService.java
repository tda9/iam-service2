package com.da.iam.service;

import com.da.iam.repo.RoleRepo;
import com.da.iam.repo.UserRepo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
@Slf4j
@RequiredArgsConstructor
public abstract class BaseService {
    protected final UserRepo userRepo;
    protected final RoleRepo roleRepo;
    protected void checkEmailExisted(String email){
        if (userRepo.existsByEmail(email)) {
            throw new IllegalArgumentException("Email existed");
        }
    }
    protected List<UUID> getRoles(Set<String> requestRoles) {
        return requestRoles.stream()
                .map(String::trim)
                .map(roleRepo::findRoleIdByName)
                .peek(role -> {
                    if(role.isEmpty() || roleRepo.findById(role.get()).get().isDeleted()){
                        log.error("------Error at getRoles()-----");
                        throw new IllegalArgumentException("Role not found");
                    }
                })
                .map(Optional::get)
                .toList();
    }
}
