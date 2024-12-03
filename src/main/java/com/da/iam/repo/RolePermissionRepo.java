package com.da.iam.repo;

import com.da.iam.entity.Permission;
import com.da.iam.entity.RolePermissions;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Set;
import java.util.UUID;

@Repository
public interface RolePermissionRepo extends JpaRepository<RolePermissions,Integer> {

    List<RolePermissions> findAllByRoleIdIn(Set<UUID> roleId);
    @Modifying
    @Query("UPDATE RolePermissions rp SET rp.resourceCode = :resourceCode, rp.scope = :scope WHERE rp.permissionId = :permissionId")
    int updateResourceCodeAndScopeByPermissionId(@Param("resourceCode") String resourceCode,
                                                 @Param("scope") String scope,
                                                 @Param("permissionId") UUID permissionId);

    void deleteByRoleId(UUID roleId);
}
