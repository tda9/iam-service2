package com.da.iam.repo;

import com.da.iam.entity.Permission;
import com.da.iam.entity.Scope;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface PermissionRepo extends JpaRepository<Permission, UUID> {
    Optional<Permission> findByResourceNameIgnoreCase(String resourceName);

    boolean existsPermissionsByResourceCodeAndResourceNameAndScopeAndPermissionIdNot(String resourceCode, String resourceName, Scope scope, UUID permissionId);

//    boolean existsPermissionsByResourceCodeAndScopeAndResourceNameNot(String resourceCode, String resourceName, String scope);
    @Transactional
    @Modifying
    @Query("UPDATE Permission p SET p.resourceCode = :resourceCode, p.scope = :scope, p.resourceName = :resourceName,p.deleted = :deleted WHERE p.permissionId = :permissionId")
    int updatePermissionById(@Param("permissionId") UUID permissionId,
                              @Param("resourceCode") String resourceCode,
                              @Param("scope") String scope,
                              @Param("resourceName") String resourceName,
                              @Param("deleted") boolean deleted);
    @Transactional
    @Modifying
    @Query("UPDATE Permission p SET p.resourceCode = :resourceCode, p.scope = :scope,p.deleted = :deleted WHERE p.resourceName = :resourceName")
    int updatePermissionByResourceName(@Param("resourceCode") String resourceCode,
                             @Param("scope") String scope,
                             @Param("resourceName") String resourceName,
                             @Param("deleted") boolean deleted);
    @Transactional
    @Modifying
    @Query("UPDATE Permission p SET p.deleted = true WHERE p.permissionId = :permissionId")
    int deletePermissionById(@Param("permissionId") UUID permissionId);

    boolean existsByResourceName(String resourceName);
    boolean existsByPermissionId(UUID permissionId);
}
