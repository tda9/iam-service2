package com.da.iam.service;

import com.da.iam.dto.request.PermissionDTO;
import com.da.iam.dto.request.RoleDTO;
import com.da.iam.dto.response.BasedResponse;
import com.da.iam.entity.Permission;
import com.da.iam.entity.Role;
import com.da.iam.entity.RolePermissions;
import com.da.iam.repo.PermissionRepo;
import com.da.iam.repo.RolePermissionRepo;
import com.da.iam.repo.RoleRepo;
import com.da.iam.utils.InputUtils;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RoleService {
    private final RoleRepo roleRepo;
    private final PermissionRepo permissionRepo;
    private final RolePermissionRepo rolePermissionRepo;
    public Set<Role> getRolesByUserId(UUID id){
        return roleRepo.findRolesByUserId(id);
    }

    public BasedResponse<?> searchAllByName(String name){
        return BasedResponse.builder()
                .httpStatusCode(200)
                .requestStatus(true)
                .data(roleRepo.findRoleByName(name))
                .build();
    }
    public BasedResponse<?> create(RoleDTO roleDTO){
        InputUtils.isValidRoleDTO(roleDTO);
        String name = roleDTO.getName();
        if(roleRepo.findByNameIgnoreCase(name).isPresent()){
            throw new IllegalArgumentException("Role existed");
        }
        try {
            roleRepo.save(Role.builder().name(name).build());
            UUID roleId = roleRepo.findRoleByName(name).getRoleId();
        Set<RolePermissions> rolePermissions = new HashSet<>();
        if(roleDTO.getPermissions()!=null && !roleDTO.getPermissions().isEmpty()){
            for(String p : roleDTO.getPermissions()){
                UUID permissionId = permissionRepo.findByNameIgnoreCase(p).orElseThrow(()-> new IllegalArgumentException("Permission for role not found")).getPermissionId();
                rolePermissions.add(RolePermissions.builder().roleId(roleId).permissionId(permissionId).build());
            }
            rolePermissionRepo.saveAll(rolePermissions);
        }


        }catch(Exception ex){
            throw new IllegalArgumentException("Create role failed");
        }
        return BasedResponse.builder()
                .httpStatusCode(201)
                .requestStatus(true)
                .data(roleRepo.findByNameIgnoreCase(name))
                .message("Create role successful")
                .build();
    }
    @Transactional
    public BasedResponse<?> updateById(RoleDTO roleDTO){
        InputUtils.isValidRoleDTO(roleDTO);
        String name = roleDTO.getName();
        UUID id = roleDTO.getRoleId();
        if(id==null || id.toString().isEmpty() ||
                roleRepo.findById(id).isEmpty()
                || !roleRepo.findRoleByNameExceptId(name,id).isEmpty()){
            throw new IllegalArgumentException("Invalid Role");
        }
        try {
            roleRepo.updateRoleById(id,name);
        }catch(Exception ex){
            throw new IllegalArgumentException("Update role failed");
        }

        return BasedResponse.builder()
                .httpStatusCode(200)
                .requestStatus(true)
                .message("Update successful")
                .data(roleRepo.findByNameIgnoreCase(name))
                .build();
    }
}
