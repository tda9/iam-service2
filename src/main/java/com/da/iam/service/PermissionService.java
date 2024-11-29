package com.da.iam.service;

import com.da.iam.dto.request.PermissionDTO;
import com.da.iam.dto.response.BasedResponse;
import com.da.iam.entity.Permission;
import com.da.iam.repo.PermissionRepo;
import com.da.iam.utils.InputUtils;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class PermissionService {
    private final PermissionRepo permissionRepo;

    //    public Page<Permission> searchAllByName(String name, Pageable pageable){
//        return permissionRepo.findAllByNameContainsIgnoreCase(name, pageable);
//    }
//    public Page<Permission> getAll(Pageable pageable){
//        return permissionRepo.findAll(pageable);
//    }
//
//    public BasedResponse<?> create(PermissionDTO permissionDTO){
//        InputUtils.isValidPermissionDTO(permissionDTO);
//        String name = permissionDTO.getName();
//        if(permissionRepo.findByNameIgnoreCase(name).isPresent()){
//            throw new IllegalArgumentException("Permission existed");
//        }
//        try {
//            permissionRepo.save(Permission.builder().name(name).build());
//        }catch(Exception ex){
//            throw new IllegalArgumentException("Create permission failed");
//        }
//        return BasedResponse.builder()
//                .httpStatusCode(201)
//                .requestStatus(true)
//                .data(permissionRepo.findByNameIgnoreCase(name))
//                .message("Create permission successful")
//                .build();
//    }
//
//    @Transactional
//    public BasedResponse<?> updateById(PermissionDTO permissionDTO){
//        InputUtils.isValidPermissionDTO(permissionDTO);
//        String name = permissionDTO.getName();
//        UUID id = permissionDTO.getPermissionId();
//        if(id==null || id.toString().isEmpty() ||
//                permissionRepo.findById(id).isEmpty()
//                || !permissionRepo.findPermissionsByNameExceptId(name,id).isEmpty()){
//            throw new IllegalArgumentException("Invalid Permission");
//        }
//        try {
//            permissionRepo.updatePermissionById(id,name);
//        }catch(Exception ex){
//            throw new IllegalArgumentException("Update permission failed");
//        }
//
//        return BasedResponse.builder()
//                .httpStatusCode(200)
//                .requestStatus(true)
//                .message("Update successful")
//                .data(permissionRepo.findByNameIgnoreCase(name))
//                .build();
//    }
//
//    @Transactional
//    public BasedResponse<?> deletePermission(PermissionDTO permissionDTO){
//        InputUtils.isValidPermissionDTO(permissionDTO);
//        String name = permissionDTO.getName();
//        if(permissionRepo.findByNameIgnoreCase(name).isEmpty()){
//            throw new IllegalArgumentException("Invalid Permission");
//        }
//        try {
//            permissionRepo.deletePermissionByName(name,true);
//        }catch(Exception ex){
//            throw new IllegalArgumentException("Soft delete permission failed");
//        }
//
//        return BasedResponse.builder()
//                .httpStatusCode(200)
//                .requestStatus(true)
//                .message("Soft deleted successful")
//                .data(permissionRepo.findByNameIgnoreCase(name))
//                .build();
//    }
    public BasedResponse<?> create(PermissionDTO permissionDTO) {
        InputUtils.isValidPermissionDTO(permissionDTO);
        String resourceCode = permissionDTO.getResourceCode();
        if (permissionRepo.findByResourceCodeIgnoreCase(resourceCode).isPresent()) {
            throw new IllegalArgumentException("Permission's resource code existed");
        }
        try {
            permissionRepo.save(Permission.builder()
                    .resourceCode(resourceCode)
                    .resourceName(permissionDTO.getResourceName())
                    .scope(permissionDTO.getScope())
                    .deleted(permissionDTO.isDeleted())
                    .build());
        } catch (Exception ex) {
            throw new IllegalArgumentException("Create permission failed");
        }
        return BasedResponse.builder()
                .httpStatusCode(201)
                .requestStatus(true)
                .data(permissionRepo.findByResourceCodeIgnoreCase(resourceCode))
                .message("Create permission successful")
                .build();
    }

    @Transactional
    public BasedResponse<?> updateById(PermissionDTO permissionDTO) {
        InputUtils.isValidPermissionDTO(permissionDTO);
        String name = permissionDTO.getResourceCode();
        String scope = permissionDTO.getScope();
        UUID id = permissionDTO.getPermissionId();
        if (id == null || id.toString().isEmpty() || permissionRepo.findById(id).isEmpty()
                || permissionRepo.checkExistedPermission(name, id).isPresent()) {
            throw new IllegalArgumentException("Invalid Permission");
        }
        try {
            permissionRepo.updatePermissionById(id, name, scope);
        } catch (Exception ex) {
            throw new IllegalArgumentException("Update permission failed");
        }

        return BasedResponse.builder()
                .httpStatusCode(200)
                .requestStatus(true)
                .message("Update successful")
                .data(permissionRepo.findByResourceCodeIgnoreCase(name))
                .build();
    }

    @Transactional
    public BasedResponse<?> deletePermission(PermissionDTO permissionDTO) {
        InputUtils.isValidPermissionDTO(permissionDTO);
        String name = permissionDTO.getResourceCode();
        if (permissionRepo.findByResourceCodeIgnoreCase(name).isEmpty()) {
            throw new IllegalArgumentException("Invalid Permission");
        }
        try {
            permissionRepo.deletePermissionByResourceCode(name);
        } catch (Exception ex) {
            throw new IllegalArgumentException("Soft delete permission failed");
        }
        return BasedResponse.builder()
                .httpStatusCode(200)
                .requestStatus(true)
                .message("Soft deleted successful")
                .data(permissionRepo.findByResourceCodeIgnoreCase(name))
                .build();
    }
}
