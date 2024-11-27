package com.da.iam.service;

import com.da.iam.entity.Role;
import com.da.iam.repo.RoleRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RoleService {
    private final RoleRepo roleRepo;

    public Set<Role> getRolesByUserId(UUID id){
        return roleRepo.findRolesByUserId(id);
    }
}
