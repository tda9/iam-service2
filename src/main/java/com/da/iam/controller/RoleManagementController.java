package com.da.iam.controller;

import com.da.iam.dto.request.CreateRoleRequest;
import com.da.iam.dto.request.DeleteRoleRequest;
import com.da.iam.dto.request.UpdateRoleRequest;
import com.da.iam.dto.response.BasedResponse;
import com.da.iam.service.RoleService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/roles")
@RequiredArgsConstructor
public class RoleManagementController {

    private final RoleService roleService;
    @PreAuthorize("hasPermission('ROLES','CREATE')")
    @PostMapping("/create")
    public BasedResponse<?> create(@RequestBody @Valid CreateRoleRequest createRoleRequest) {
        return roleService.create(createRoleRequest);
    }
    @PreAuthorize("hasPermission('ROLES','UPDATE')")
    @PutMapping("/update")
    public BasedResponse<?> updateById(@RequestBody @Valid UpdateRoleRequest request){
        return roleService.updateById(request);
    }
    @PreAuthorize("hasPermission('ROLES','DELETE')")
    @DeleteMapping("/delete")
    public BasedResponse<?> deleteById(@RequestBody @Valid DeleteRoleRequest request){
        return roleService.deleteById(request);
    }
    @PreAuthorize("hasPermission('ROLES','READ')")
    @GetMapping("/{id}")
    public BasedResponse<?> findById(@PathVariable @Valid String id){
        return roleService.findById(id);
    }

    @GetMapping("/{name}")
    public BasedResponse<?> findByName(@PathVariable @Valid String name){
        return roleService.findByName(name);
    }
}
