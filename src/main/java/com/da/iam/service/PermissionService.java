package com.da.iam.service;

import com.da.iam.dto.request.CreatePermissionRequest;
import com.da.iam.dto.request.DeletePermissionRequest;
import com.da.iam.dto.request.UpdatePermissionRequest;
import com.da.iam.dto.response.BasedResponse;
import com.da.iam.entity.Permission;
import com.da.iam.entity.Scope;
import com.da.iam.exception.SaveToDatabaseFailedException;
import com.da.iam.repo.PermissionRepo;
import com.da.iam.repo.RolePermissionRepo;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class PermissionService {
    private final PermissionRepo permissionRepo;
    private final RolePermissionRepo rolePermissionRepo;

    public Permission findById(String id){
        return permissionRepo.findById(UUID.fromString(id)).orElseThrow(()->new IllegalArgumentException("Permission not found"));
    }
    public BasedResponse<?> create(CreatePermissionRequest request) {
        log.info("-------------------------------" + SecurityContextHolder.getContext().getAuthentication().getName() + " create permission");
        String name = request.resourceName();
        if (permissionRepo.existsByResourceName(name)) {
            throw new IllegalArgumentException("Resource name existed");
        }
        try {
            Permission permission = Permission.builder()
                    .resourceCode(request.resourceCode())
                    .resourceName(request.resourceName())
                    .scope(request.scope())
                    .build();
            permissionRepo.save(permission);
            return BasedResponse.created("Create permission successful", permissionRepo.findByResourceNameIgnoreCase(name).orElseThrow());
        } catch (Exception ex) {
            log.error(ex.getMessage());
            log.info("-------------------------------" + SecurityContextHolder.getContext().getAuthentication().getName() + "failed create permission");
            throw new SaveToDatabaseFailedException("Create permission failed: " + ex.getMessage());
        }

    }

    @Transactional
    public BasedResponse<?> updateById(UpdatePermissionRequest request) {
        UUID id = UUID.fromString(request.permissionId());
        String resourceName = request.resourceName();
        String scope = request.scope();
        String resourceCode = request.resourceCode();
        boolean deleted = request.deleted();
        if (!permissionRepo.existsByPermissionId(id)) {//kiem tra co ton tai ko
            throw new IllegalArgumentException("Permission id not found");
        } else if (permissionRepo.existsPermissionsByResourceCodeAndResourceNameAndScopeAndPermissionIdNot(resourceCode, resourceName, scope, id)) {//kiem tra co trung permission khac ko
            throw new IllegalArgumentException("Permission field existed");
        }
        try {
            Permission permission = permissionRepo.findById(id).orElseThrow(() -> new IllegalArgumentException("HERE"));
            permission.setDeleted(deleted);
            permission.setScope(Scope.valueOf(scope));
            permission.setResourceName(resourceName);
            permission.setResourceCode(resourceCode);
            permissionRepo.save(permission);
            // this will not work with auditorAware isOperationSuccess(permissionRepo.updatePermissionById(id, resourceCode, scope, resourceName, deleted), "Update permission failed");//update va kiem tra permission
            rolePermissionRepo.updateResourceCodeAndScopeByPermissionId(resourceCode, scope, id);//update lai role_permission
            return BasedResponse.success("Update successful", permissionRepo.findByResourceNameIgnoreCase(resourceName).orElseThrow());
        } catch (Exception ex) {
            throw new IllegalArgumentException("Update permission failed: " + ex
                    .getMessage());
        }
    }
//    @Transactional
//    public BasedResponse<?> updateByResourceName(UpdatePermissionRequest request) {
//        String resourceName = request.resourceName();
//        String scope = request.scope();
//        String resourceCode = request.resourceCode();
//        boolean deleted = request.deleted();
//        if (!permissionRepo.existsByResourceName(resourceName)) {
//            throw new IllegalArgumentException("Permission resource name not found");
//        } else if (permissionRepo.existsPermissionsByResourceCodeAndScopeAndResourceNameNot(resourceCode, resourceName, scope)) {
//            throw new IllegalArgumentException("Permission field existed");
//        }
//        try {
//            isOperationSuccess(permissionRepo.updatePermissionByResourceName(resourceCode, scope, resourceName, deleted), "Update permission failed");
//            return new BasedResponse().success("Update successful", permissionRepo.findByResourceNameIgnoreCase(resourceName).orElseThrow());
//        } catch (Exception ex) {
//            throw new IllegalArgumentException("Update permission failed");
//        }
//    }

    @Transactional
    public BasedResponse<?> deleteById(DeletePermissionRequest request) {
        UUID id = UUID.fromString(request.permissionId());
        if (permissionRepo.existsByPermissionId(id)) {
            throw new IllegalArgumentException("Permission id not found");
        }
        try {
            isOperationSuccess(permissionRepo.deletePermissionById(id), "Delete permission failed");
            return BasedResponse.success("Deleted successful", permissionRepo.findById(id).orElseThrow());
        } catch (Exception ex) {
            throw new IllegalArgumentException("Delete permission failed");
        }
    }

    private void isOperationSuccess(int isSuccess, String message) {
        if (isSuccess == 0) {
            throw new IllegalArgumentException(message);
        }
    }

    @Value("${permission.scopes}")
    private String scopes;

    public List<String> getScopes() {
        return List.of(scopes.split("\\|"));
    }
}
