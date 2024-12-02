package com.da.iam.controller;


import com.da.iam.dto.request.CreatePermissionRequest;
import com.da.iam.dto.request.DeletePermissionRequest;
import com.da.iam.dto.request.UpdatePermissionRequest;
import com.da.iam.dto.response.BasedResponse;
import com.da.iam.service.PermissionService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
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
    public BasedResponse<?> create(@RequestBody @Valid CreatePermissionRequest permissionDTO) {
        return permissionService.create(permissionDTO);
    }

    @PutMapping("/permissions")
    public BasedResponse<?> updateById(@RequestBody @Valid UpdatePermissionRequest request){
        return permissionService.updateById(request);
    }

//    @PutMapping("/permissions/resource-name")
//    public BasedResponse<?> updateByResourceName(@RequestBody @Valid UpdatePermissionRequest request){
//        return permissionService.updateByResourceName(request);
//    }

    @DeleteMapping("/permissions/id")
    public BasedResponse<?> deleteById(@RequestBody DeletePermissionRequest request){
        return permissionService.deleteById( request);
    }
//    @DeleteMapping("/permissions/resource-name")
//    public BasedResponse<?> deleteByResourceName(@RequestBody DeletePermissionRequest request){
//        return permissionService.deleteByResourceName( request);
//    }
}
