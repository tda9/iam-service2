package com.da.iam.controller;

import com.da.iam.dto.request.PermissionDTO;
import com.da.iam.dto.request.RoleDTO;
import com.da.iam.dto.response.BasedResponse;
import com.da.iam.service.RoleService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/iam")
@RequiredArgsConstructor
public class RoleManagementController {

    private final RoleService roleService;

    //@PreAuthorize("hasAuthority('SYSTEM_MANAGER.CREATE')")
    @PostMapping("/roles")
    public BasedResponse<?> create(@RequestBody @Valid RoleDTO roleDTO) {
        return roleService.create(roleDTO);
    }

    @PreAuthorize("hasAuthority('ROLE.UPDATE')")
    @PutMapping("/roles")
    public BasedResponse<?> updateByName(@RequestBody @Valid RoleDTO roleDTO){
        return roleService.updateById(roleDTO);
    }
    @PreAuthorize("hasAuthority('ROLE.DELETE')")
    @DeleteMapping("/roles")
    public BasedResponse<?> deleteByName(@RequestParam @Valid String name){
        return roleService.deleteRoleById(name);
    }
}
