package com.da.iam.service;

import com.da.iam.entity.*;
import com.da.iam.repo.PermissionRepo;
import com.da.iam.repo.RolePermissionRepo;
import com.da.iam.repo.RoleRepo;
import com.da.iam.repo.UserRepo;
//import com.da.iam.repo.UserRoleRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
    private final UserRepo userRepo;
    private final RoleRepo roleRepo;
    private final PermissionRepo permissionRepo;
    private final RolePermissionRepo rolePermissionRepo;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepo.findByEmail(email).orElseThrow(() -> new UsernameNotFoundException("User not found"));
        if (user == null) {
            throw new UsernameNotFoundException("User not found");
        }
        Set<GrantedAuthority> authorities = new HashSet<>();
        Set<Role> userRoles = roleRepo.findRolesByUserId(user.getUserId());
        List<RolePermissions> rolePermissions = rolePermissionRepo.findAllByRoleIdIn(userRoles.stream().map(Role::getRoleId).collect(Collectors.toSet()));
        return new CustomUserDetails(user.getEmail(),
                user.getPassword(),
                mapRolesToAuthorities(userRoles,rolePermissions), user.isLock());
    }
    public Collection<? extends GrantedAuthority> mapRolesToAuthorities(Set<Role> roles, List<RolePermissions> permissions) {
        // Map roles to authorities
        Stream<GrantedAuthority> roleAuthorities = roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.getName()));

        // Flatten the nested List<Permission> in the Set and map them to authorities
        Stream<GrantedAuthority> permissionAuthorities = permissions.stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getResourceCode()+"."+permission.getScope()));
        return Stream.concat(roleAuthorities, permissionAuthorities).collect(Collectors.toSet());
    }
}
