package com.da.iam.repo;

import com.da.iam.entity.RolePermissions;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RolePermissionRepo extends JpaRepository<RolePermissions,Integer> {
}
