package com.da.iam.service;

import com.da.iam.dto.request.CreateRoleRequest;
import com.da.iam.dto.request.DeletePermissionRequest;
import com.da.iam.dto.request.DeleteRoleRequest;
import com.da.iam.dto.request.UpdateRoleRequest;
import com.da.iam.dto.response.BasedResponse;
import com.da.iam.entity.Permission;
import com.da.iam.entity.Role;
import com.da.iam.entity.RolePermissions;
import com.da.iam.repo.PermissionRepo;
import com.da.iam.repo.RolePermissionRepo;
import com.da.iam.repo.RoleRepo;
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

    @Transactional
    public BasedResponse<?> create(CreateRoleRequest request) {
        String name = request.name();
        if (roleRepo.existsByName(name)) {
            throw new IllegalArgumentException("Role name existed");
        }
        Set<Permission> permissions = getPermissions(request.permissionsResourceName());
        try {
            roleRepo.save(Role.builder().name(name).build());
            UUID roleId = roleRepo.findRoleIdByName(name).orElseThrow(() -> new IllegalArgumentException("Role id not found after create role"));
            Set<RolePermissions> rolePermissions = new HashSet<>();
            fetchRolePermissions(rolePermissions, roleId, permissions);
            rolePermissionRepo.saveAll(rolePermissions);
            return BasedResponse.created("Create role successful",rolePermissions);
        } catch (Exception ex) {
            throw new IllegalArgumentException("Create role failed");
        }
    }

    @Transactional
    public BasedResponse<?> updateById(UpdateRoleRequest request) {
        Set<Permission> permissions = getPermissions(request.permissionsResourceName());
        String name = request.name();
        UUID id = UUID.fromString(request.roleId());
        boolean deleted = request.deleted();
        if (!roleRepo.existsById(id)) {
            throw new IllegalArgumentException("Role id not found");
        } else if (roleRepo.existsByNameAndRoleIdNot(name, id)) {
            throw new IllegalArgumentException("Role name existed");
        }
        try {
            isOperationSuccess(roleRepo.updateRoleById(id, name, deleted), "Update role failed");
            Set<RolePermissions> rolePermissions = new HashSet<>();
            fetchRolePermissions(rolePermissions, id, permissions);
            rolePermissionRepo.deleteByRoleId(id);
            rolePermissionRepo.saveAll(rolePermissions);
            return BasedResponse.success("Update successful", rolePermissions);
        } catch (Exception ex) {
            throw new IllegalArgumentException("Update role failed");
        }
    }

    @Transactional
    public BasedResponse<?> deleteById(DeleteRoleRequest request) {
        UUID id = UUID.fromString(request.roleId());
        if (!roleRepo.existsById(id)) {
            throw new IllegalArgumentException("Role id not found");
        }
        try {
            isOperationSuccess(roleRepo.softDeleteRoleById(id), "Delete role failed");
            return BasedResponse.success("Deleted successful", roleRepo.findById(id).orElseThrow());
        } catch (Exception ex) {
            throw new IllegalArgumentException("Delete role failed");
        }

    }

    public BasedResponse<?> findById(String id){
        Role role = roleRepo.findById(UUID.fromString(id)).orElseThrow(()-> new IllegalArgumentException("Role not found"));
        return BasedResponse.success("Role found",role);
    }
    public BasedResponse<?> findByName(String name){
        //Role role = roleRepo.findById(UUID.fromString(id)).orElseThrow(()-> new IllegalArgumentException("Role not found"));
        return BasedResponse.success("Role found",null);
    }

    private Set<Permission> getPermissions(Set<String> rqPermission) {
        Set<Permission> permissionsSet = new HashSet<>();
        rqPermission.stream()
                .map(String::trim) // Trim each permission name
                .map(permissionRepo::findByResourceNameIgnoreCase)
                .peek(permission -> {
                    if (permission.isEmpty()||permission.get().isDeleted()) {
                        throw new IllegalArgumentException("Permission not found");
                    }
                })
                .map(Optional::get)
                .forEach(permissionsSet::add);
        return permissionsSet;
    }

    private void fetchRolePermissions(Set<RolePermissions> rolePermissions, UUID roleId, Set<Permission> permissions) {
        permissions.stream().map(permission -> RolePermissions.builder()
                        .roleId(roleId)
                        .permissionId(permission.getPermissionId())
                        .scope(permission.getScope())
                        .resourceCode(permission.getResourceCode())
                        .build())
                .forEach(rolePermissions::add);
    }

    private void isOperationSuccess(int isSuccess, String message) {
        if (isSuccess == 0) {
            throw new IllegalArgumentException(message);
        }
    }
}
