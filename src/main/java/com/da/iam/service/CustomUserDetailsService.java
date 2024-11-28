package com.da.iam.service;

import com.da.iam.entity.Permission;
import com.da.iam.entity.Role;
import com.da.iam.entity.User;
import com.da.iam.entity.UserRoles;
import com.da.iam.repo.PermissionRepo;
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

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
    private final UserRepo userRepo;
    private final RoleRepo roleRepo;
    private final PermissionRepo permissionRepo;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepo.findByEmail(email).orElseThrow(() -> new UsernameNotFoundException("User not found"));
        if (user == null) {
            throw new UsernameNotFoundException("User not found");
        }
        Set<GrantedAuthority> authorities = new HashSet<>();
        Set<Role> userRoles = roleRepo.findRolesByUserId(user.getUserId());
        Set<List<Permission>> rolePermissions = new HashSet<>();
        for(Role r : userRoles){
            rolePermissions.add(roleRepo.findRolePermission(r.getRoleId()));
        }
        return new CustomUserDetails(user.getEmail(),
                user.getPassword(),
                mapRolesToAuthorities(userRoles,rolePermissions));
    }
    public Collection<? extends GrantedAuthority> mapRolesToAuthorities(Set<Role> roles, Set<List<Permission>> permissions) {
        // Map roles to authorities
        Stream<GrantedAuthority> roleAuthorities = roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.getName()));

        // Flatten the nested List<Permission> in the Set and map them to authorities
        Stream<GrantedAuthority> permissionAuthorities = permissions.stream()
                .flatMap(List::stream) // Flatten the list of permissions
                .map(permission -> new SimpleGrantedAuthority(permission.getName()));
        return Stream.concat(roleAuthorities, permissionAuthorities).collect(Collectors.toSet());
    }
}
