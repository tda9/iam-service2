package com.da.iam.controller;


import com.da.iam.controller.factory.UserServiceFactory;
import com.da.iam.dto.request.CreateUserRequest;
import com.da.iam.dto.request.SearchUserRequest;
import com.da.iam.dto.request.UpdateUserRequest;
import com.da.iam.dto.response.BasedResponse;
import com.da.iam.dto.response.PageResponse;
import com.da.iam.entity.User;
import com.da.iam.service.impl.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

import org.springframework.data.domain.Page;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("/users")
public class UserManagementController {
    private final UserServiceFactory userServiceFactory;
    private final UserService userService;

    //    @PreAuthorize("hasAnyRole('USER','ADMIN')")
//    @GetMapping("/user")
//    public BasedResponse<?> getUser(@RequestParam String email) {
//        InputUtils.isValidEmail(email);
//        User user = userService.getUserByEmail(email);
//
//        UserDto userDto = new UserDto(user);
//        userDto.setRoles(roleService.getRolesByUserId(user.getUserId()));
//        return BasedResponse.builder()
//                .requestStatus(true)
//                .httpStatusCode(200)
//                .data(EntityModel.of(userDto, linkTo(WebMvcLinkBuilder.methodOn(UserManagementController.class).getUser(email)).withSelfRel()))
//                .build();
//    }
//
//    @PreAuthorize("hasRole('ADMIN')")
//    @GetMapping("/users")
//    public ResponseEntity<CollectionModel<EntityModel<UserDto>>> getUsers() {
//        Iterable<User> userEntities = userService.getUsers();
//        if (userEntities == null || !userEntities.iterator().hasNext()) {
//            throw new UserNotFoundException("No users found");
//        }
//        List<EntityModel<UserDto>> users = new ArrayList<>();
//        toCollectionModel(userEntities, users);
//        return ResponseEntity.ok(CollectionModel.of(users, linkTo(WebMvcLinkBuilder.methodOn(UserManagementController.class).getUsers()).withSelfRel()));
//    }
//
//    @PreAuthorize("hasAnyRole('USER','ADMIN')")
//    @PutMapping("/users")
//    public ResponseEntity<EntityModel<?>> updateUser(@RequestBody UserProfile userProfile) {
//        User updatedUser = null;
//        try {
//            updatedUser = userService.updateUser(userProfile);
//        } catch (Exception e) {
//            throw new ErrorResponseException("Error user profile");
//        }
//        return ResponseEntity.ok(EntityModel.of(updatedUser, linkTo(WebMvcLinkBuilder.methodOn(UserManagementController.class).getUser(updatedUser.getEmail())).withSelfRel()));
//    }
//
//    @PreAuthorize("hasRole('ADMIN')")
//    @DeleteMapping("/users")
//    public ResponseEntity<?> deleteUser(@RequestParam Long id) {
//        User user = userService.getUserById(id);
//        if (user == null) {
//            return ResponseEntity.status(400).body(Map.of("User not found", id));
//        }
//        Set<Role> roles = roleService.getRolesByUserId(user.getUserId());
//        UserDto userDto = new UserDto(user);
//        userDto.setRoles(roles);
//        userService.deleteUser(id);
//        userRoleRepo.deleteByUserId(id);
//        return ResponseEntity.status(200).body(Map.of("Deleted successful", userDto));
//    }
//
//    private void toCollectionModel(Iterable<User> userEntities, List<EntityModel<UserDto>> users) {
//        for (User user : userEntities) {
//            UserDto userDto = new UserDto(user);
//            userDto.setRoles(roleService.getRolesByUserId(user.getUserId()));
//            users.add(EntityModel.of(userDto, linkTo(WebMvcLinkBuilder.methodOn(UserManagementController.class).getUser(user.getEmail())).withSelfRel()));
//        }
//    }
    @PreAuthorize("hasPermission('USERS','CREATE')")
    @PostMapping("/create")
    public BasedResponse<?> create(@RequestBody @Valid CreateUserRequest request) {
        return new BasedResponse().success("Create successful",
                userServiceFactory.getUserService().create(request));
    }
    @PreAuthorize("hasPermission('USERS','UPDATE')")
    @PutMapping("/update")
    public BasedResponse<?> updateById(@RequestBody @Valid UpdateUserRequest request) {
        return userServiceFactory.getUserService().updateById(request);
    }
    @GetMapping("/search")
    public BasedResponse<?> searchByKeyword(
            @RequestBody @Valid SearchUserRequest request,
            @RequestParam(required = false, defaultValue = "0") int currentPage,
            @RequestParam(required = false, defaultValue = "1") int currentSize,
            @RequestParam(required = false, defaultValue = "email") String sortBy,
            @RequestParam(required = false, defaultValue = "ASC") String sort
    ) {
        Page<User> users = userService.searchByKeyword(request, currentPage, currentSize, sortBy, sort);
        return new PageResponse<>(currentPage, users.getTotalPages(), currentSize, users.getTotalElements(), sortBy, sort, List.of(users.get()));
    }
}
