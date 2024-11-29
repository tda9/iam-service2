package com.da.iam.repo;

import com.da.iam.entity.Permission;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface PermissionRepo extends JpaRepository<Permission, UUID> {
    Optional<Permission> findByResourceCodeIgnoreCase(String resourceCode);
    Optional<Permission> findByResourceNameIgnoreCase(String resourceName);

    @Modifying
    @Query("SELECT p FROM Permission p WHERE p.resourceCode = :resourceCode AND p.permissionId != :permissionId")
    Optional<Permission> checkExistedPermission(String resourceCode,UUID permissionId);

    @Modifying
    @Query("UPDATE Permission p SET p.resourceCode = :resourceCode, p.scope = :scope WHERE p.permissionId = :permissionId")
    void updatePermissionById(@Param("permissionId") UUID permissionId, @Param("resourceCode") String resourceCode,@Param("scope") String scope);

    @Modifying
    @Query("UPDATE Permission p SET p.deleted = true WHERE p.resourceCode = :resourceCode")
    void deletePermissionByResourceCode(@Param("resourceCode") String resourceCode);

//    Page<Permission> findAllByNameContainsIgnoreCase(String name, Pageable pageable);
//
//
//    @Modifying
//    @Query("UPDATE Permission p SET p.name = :name WHERE p.permissionId = :permissionId")
//    void updatePermissionById(@Param("permissionId") UUID permissionId, @Param("name") String name);
//
//    Optional<Permission> findByNameIgnoreCase(String name);
//
//    @Modifying
//    @Query("UPDATE Permission p SET p.deleted = :deleted WHERE p.name = :name")
//    void deletePermissionByName(@Param("name") String name,
//                                @Param("deleted") boolean deleted);
//
//    @Query("SELECT p FROM Permission p WHERE p.name = :name AND p.permissionId != :id")
//    List<Permission> findPermissionsByNameExceptId(@Param("name") String name,
//                                                   @Param("id") UUID id);
//

}
