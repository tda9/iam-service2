package com.da.iam.repo;

import com.da.iam.entity.Permission;
import com.da.iam.entity.RolePermissions;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Set;
import java.util.UUID;

@Repository
public interface RolePermissionRepo extends JpaRepository<RolePermissions,Integer> {
    List<RolePermissions> findAllByRoleId(UUID roleId);
}
