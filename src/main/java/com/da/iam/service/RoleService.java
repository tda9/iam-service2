package com.da.iam.service;

import com.da.iam.dto.request.RoleDTO;
import com.da.iam.dto.response.BasedResponse;
import com.da.iam.dto.response.RoleDtoResponse;
import com.da.iam.dto.response.RolePermissionDtoResponse;
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
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RoleService {
    private final RoleRepo roleRepo;
    private final PermissionRepo permissionRepo;
    private final RolePermissionRepo rolePermissionRepo;

    public Set<Role> getRolesByUserId(UUID id) {
        return roleRepo.findRolesByUserId(id);
    }

    public BasedResponse<?> searchAllByName(String name) {
        return BasedResponse.builder()
                .httpStatusCode(200)
                .requestStatus(true)
                .data(roleRepo.findRoleByName(name))
                .build();
    }

    public BasedResponse<?> create(RoleDTO roleDTO) {
        InputUtils.isValidRoleDTO(roleDTO);
        String name = roleDTO.getName();
        if (roleRepo.findByNameIgnoreCase(name).isPresent()) {
            throw new IllegalArgumentException("Role existed");
        }
        Set<Permission> permissions;
        Set<RolePermissions> rolePermissions = new HashSet<>();;
        Set<RolePermissionDtoResponse> rolePermissionDtoResponse = new HashSet<>();


        if (roleDTO.getPermissionsResourceName() != null && !roleDTO.getPermissionsResourceName().isEmpty()) {
            permissions = getPermission(roleDTO.getPermissionsResourceName());

        try {
            roleRepo.save(Role.builder().name(name).build());
            UUID roleId = roleRepo.findRoleByName(name).getRoleId();

                for (Permission permission : permissions) {
                    RolePermissions rP1 = RolePermissions.builder()
                            .roleId(roleId)
                            .permissionId(permission.getPermissionId())
                            .scope(permission.getScope())
                            .resourceCode(permission.getResourceCode())
                            .build();
                    rolePermissions.add(rP1);
                    rolePermissionDtoResponse.add(RolePermissionDtoResponse.builder()
                            .permissionId(permission.getPermissionId())
                            .scope(permission.getScope())
                            .resourceCode(permission.getResourceCode())
                            .resourceName(permission.getResourceName())
                            .build());
                }
                rolePermissionRepo.saveAll(rolePermissions);



        } catch (Exception ex) {
            throw new IllegalArgumentException("Create role failed");
        }}
        Role r = roleRepo.findByNameIgnoreCase(name).orElseThrow();
        return BasedResponse.builder()
                .httpStatusCode(201)
                .requestStatus(true)
                .data(RoleDtoResponse.builder()
                        .name(r.getName())
                        .rolePermissionDtoResponse(rolePermissionDtoResponse)
                        .build())

                .message("Create role successful")
                .build();
    }

    @Transactional
    public BasedResponse<?> updateById(RoleDTO roleDTO) {
        InputUtils.isValidRoleDTO(roleDTO);
        String name = roleDTO.getName();
        UUID id = roleDTO.getRoleId();
        if (id == null || id.toString().isEmpty() ||
                roleRepo.findById(id).isEmpty()
                || !roleRepo.findRoleByNameExceptId(name, id).isEmpty()) {
            throw new IllegalArgumentException("Invalid Role");
        }
        try {
            roleRepo.updateRoleById(id, name);
        } catch (Exception ex) {
            throw new IllegalArgumentException("Update role failed");
        }

        return BasedResponse.builder()
                .httpStatusCode(200)
                .requestStatus(true)
                .message("Update successful")
                .data(roleRepo.findByNameIgnoreCase(name))
                .build();
    }
    @Transactional
    public BasedResponse<?> deleteRoleById(String name) {
        Optional<Role> role = roleRepo.findByNameIgnoreCase(name);
        if (role.isPresent()) {
            throw new IllegalArgumentException("Invalid Role");
        }
        try {
            roleRepo.softDeleteRoleById(role.get().getRoleId());
        } catch (Exception ex) {
            throw new IllegalArgumentException("Delete role failed");
        }
        return BasedResponse.builder()
                .httpStatusCode(200)
                .requestStatus(true)
                .message("Delete successful")
                .data(role.get())
                .build();
    }
    private Set<Permission> getPermission(Set<String> roles) {
        Set<Permission> permissionsSet = new HashSet<>();
        for (String r : roles) {
            Optional<Permission> permission = permissionRepo.findByResourceNameIgnoreCase(r);
            if(permission.isEmpty() || permission.get().isDeleted()){
                throw new IllegalArgumentException("There is permission that was deleted or not existed");
            }
            permissionsSet.add(permission.get());
        }
        return permissionsSet;
    }


}
