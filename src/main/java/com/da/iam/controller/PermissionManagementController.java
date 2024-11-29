package com.da.iam.controller;


import com.da.iam.dto.request.PermissionDTO;
import com.da.iam.dto.response.BasedResponse;
import com.da.iam.entity.Permission;
import com.da.iam.service.PermissionService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/iam")
@RequiredArgsConstructor
public class PermissionManagementController {
    private final PermissionService permissionService;
    @GetMapping("/permissions")
    public BasedResponse<?> searchByResourceName(@RequestParam @Valid String name) {
        return BasedResponse.builder()
                .httpStatusCode(200)
                .requestStatus(true)
                .data(permissionService.searchByResourceName(name))
                .build();
    }
//    @PostMapping("/permissions")
//    public BasedResponse<Object> getAll(Pageable pageable) {
//        return BasedResponse.builder()
//                .httpStatusCode(200)
//                .requestStatus(true)
//                .data(permissionService.getAll(pageable))
//                .build();
//    }

    @PostMapping("/permissions")
    public BasedResponse<?> create(@RequestBody @Valid PermissionDTO permissionDTO) {
        return permissionService.create(permissionDTO);
    }

    @PutMapping("/permissions")
    public BasedResponse<?> updateByPermissionId(@RequestBody @Valid PermissionDTO permissionDTO){
        return permissionService.updateById(permissionDTO);
    }

    @DeleteMapping("/permissions")
    public BasedResponse<?> softDeleteByName(@RequestBody PermissionDTO permissionDTO){
        return permissionService.deletePermission(permissionDTO);
    }
}
