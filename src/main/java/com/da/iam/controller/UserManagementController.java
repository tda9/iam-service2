package com.da.iam.controller;


import com.da.iam.dto.request.CreateRoleRequest;
import com.da.iam.dto.request.CreateUserRequest;
import com.da.iam.dto.request.UpdateUserRequest;
import com.da.iam.dto.response.BasedResponse;
import com.da.iam.entity.User;
import com.da.iam.repo.UserRoleRepo;
import com.da.iam.service.KeycloakUserService;
import com.da.iam.service.RoleService;
import com.da.iam.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.hibernate.sql.Update;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class UserManagementController {
    private final UserServiceFactory userServiceFactory;

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

    @PostMapping("/users/create")
    public BasedResponse<?> create(@RequestBody @Valid CreateUserRequest request) {
        return userServiceFactory.getUserService().create(request);
    }

    @PutMapping("/users")
    public BasedResponse<?> updateById(@RequestBody @Valid UpdateUserRequest request) {
        return userServiceFactory.getUserService().updateById(request);
    }
}
