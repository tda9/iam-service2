package com.da.iam.repo;

import com.da.iam.entity.Permission;
import com.da.iam.entity.Role;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@Repository
public interface RoleRepo extends JpaRepository<Role, UUID> {

    @Query(value = "SELECT r.* FROM roles r " +
            "JOIN user_roles ur ON r.role_id = ur.role_id " +
            "WHERE ur.user_id = :userId",
            nativeQuery = true)
    Set<Role> findRolesByUserId(@Param("userId") UUID userId);

    @Query(value = "SELECT r.* FROM roles r " + "WHERE r.name = :name",
            nativeQuery = true)
    Role findRoleByName(String name);

    Optional<Role> findByNameIgnoreCase(String name);

    @Query("SELECT r FROM Role r WHERE r.name = :name AND r.roleId != :id")
    List<Role> findRoleByNameExceptId(@Param("name") String name,
               @Param("id") UUID id);
    @Transactional
    @Modifying
    @Query("UPDATE Role p SET p.name = :name WHERE p.roleId = :roleId")
    void updateRoleById(@Param("roleId") UUID roleId, @Param("name") String name);

    @Query("SELECT p FROM Permission p RIGHT JOIN RolePermissions rp ON rp.permissionId = p.permissionId WHERE rp.roleId = :roleId")
    Set<Permission> findRolePermission(@Param("roleId") UUID roleId);

    @Transactional
    @Modifying
    @Query("UPDATE Role p SET p.deleted = true WHERE p.roleId = :roleId")
    int softDeleteRoleById(@Param("roleId") UUID roleId);

}
