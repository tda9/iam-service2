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
//@RequestMapping("")
@RequiredArgsConstructor
public class RoleManagementController {

    private final RoleService roleService;

    //@PreAuthorize("hasAuthority('SYSTEM_MANAGER.CREATE')")
    @PostMapping("/roles/create")
    public BasedResponse<?> create(@RequestBody @Valid CreateRoleRequest createRoleRequest) {
        return roleService.create(createRoleRequest);
    }
    //@PreAuthorize("hasAuthority('SUPER-GUEST.UPDATE')")
    @PutMapping("/roles")
    public BasedResponse<?> updateById(@RequestBody @Valid UpdateRoleRequest request){
        return roleService.updateById(request);
    }
    //@PreAuthorize("hasAuthority('ROLE.DELETE')")
    @DeleteMapping("/roles")
    public BasedResponse<?> deleteById(@RequestBody @Valid DeleteRoleRequest request){
        return roleService.deleteById(request);
    }
}
