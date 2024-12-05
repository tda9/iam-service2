package com.da.iam.controller;


import com.da.iam.controller.factory.UserServiceFactory;
import com.da.iam.dto.request.CreateUserRequest;
import com.da.iam.dto.request.SearchUserRequest;
import com.da.iam.dto.request.UpdateUserRequest;
import com.da.iam.dto.response.BasedResponse;
import com.da.iam.dto.response.PageResponse;
import com.da.iam.dto.response.UserDtoResponse;
import com.da.iam.entity.Role;
import com.da.iam.entity.User;
import com.da.iam.entity.UserRoles;
import com.da.iam.repo.RoleRepo;
import com.da.iam.repo.UserRoleRepo;
import com.da.iam.service.RoleService;
import com.da.iam.service.impl.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Set;

@RestController
@RequiredArgsConstructor
@RequestMapping("/users")
public class UserManagementController {
    private final UserServiceFactory userServiceFactory;
    private final UserService userService;
    private final RoleRepo userRoleRepo;

    @PreAuthorize("hasPermission('USERS','CREATE')")
    @PostMapping("/create")
    public BasedResponse<?> create(@RequestBody @Valid CreateUserRequest request) {
        return BasedResponse.created("Create successful", userServiceFactory.getUserService().create(request));
    }

    @PreAuthorize("hasPermission('USERS','UPDATE')")
    @PutMapping("/update")
    public BasedResponse<?> updateById(@RequestBody @Valid UpdateUserRequest request) {
        return BasedResponse.success("Update successful", userServiceFactory.getUserService().updateById(request));
    }
    @PreAuthorize("hasPermission('USERS','READ')")
    @GetMapping("/search")
    public BasedResponse<?> searchByKeyword(
            @RequestParam String keyword,
            @RequestParam(required = false, defaultValue = "1") int currentPage,
            @RequestParam(required = false, defaultValue = "1") int currentSize,
            @RequestParam(required = false, defaultValue = "email") String sortBy,
            @RequestParam(required = false, defaultValue = "ASC") String sort
    ) {
        List<User> users = userService.searchByKeyword(keyword, sortBy, sort, currentSize, currentPage);
        Long totalSize = userService.getTotalSize(keyword);
        if(currentSize>totalSize){
         currentSize = Math.toIntExact(totalSize);
        }
        return new PageResponse<>(currentPage, ((int) (totalSize / currentSize) ), currentSize, totalSize, sortBy, sort, users);
    }

    @GetMapping("/{id}")
    public BasedResponse<?> findById(@PathVariable String id) {
        User user = userService.findById(id);
        Set<Role> roles = userRoleRepo.findRolesByUserId(user.getUserId());
        return BasedResponse.success("User found", UserDtoResponse.builder()
                .user(user)
                .roles(roles)
                .build());
    }

    @GetMapping("/absolute-search")
    public BasedResponse<?> absoluteSearch(
            @RequestParam(required = false) String keyword) {
        List<User> user = userService.searchByField(keyword);
        return BasedResponse.success("User found", user);
    }
}
