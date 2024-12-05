package com.da.iam.controller;


import com.da.iam.dto.request.CreatePermissionRequest;
import com.da.iam.dto.request.DeletePermissionRequest;
import com.da.iam.dto.request.UpdatePermissionRequest;
import com.da.iam.dto.response.BasedResponse;
import com.da.iam.service.PermissionService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/permissions")
@RequiredArgsConstructor
public class PermissionManagementController {
    private final PermissionService permissionService;
    @PreAuthorize("hasPermission('PERMISSIONS','CREATE')")
    @PostMapping("/create")
    public BasedResponse<?> create(@RequestBody @Valid CreatePermissionRequest permissionDTO) {
        return permissionService.create(permissionDTO);
    }
    @PreAuthorize("hasPermission('PERMISSIONS','UPDATE')")
    @PutMapping("/update")
    public BasedResponse<?> updateById(@RequestBody @Valid UpdatePermissionRequest request) {
        return permissionService.updateById(request);
    }
    @PreAuthorize("hasPermission('PERMISSIONS','DELETE')")
    @DeleteMapping("/delete")
    public BasedResponse<?> deleteById(@RequestBody DeletePermissionRequest request) {
        return permissionService.deleteById(request);
    }
    @PreAuthorize("hasPermission('PERMISSIONS','READ')")
    @GetMapping("/{id}")
    public BasedResponse<?> findById(@PathVariable String id) {
        return BasedResponse.success("Permission found",permissionService.findById(id));
    }
}
