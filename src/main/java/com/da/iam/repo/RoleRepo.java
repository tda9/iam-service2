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

    @Query("SELECT r.roleId FROM Role r WHERE r.name = :name")
    Optional<UUID> findRoleIdByName(String name);

    Optional<Role> findByNameIgnoreCase(String name);

    @Transactional
    @Modifying
    @Query("UPDATE Role p SET p.name = :name, p.deleted = :deleted WHERE p.roleId = :roleId")
    int updateRoleById(@Param("roleId") UUID roleId, @Param("name") String name,boolean deleted);

    @Transactional
    @Modifying
    @Query("UPDATE Role p SET p.deleted = true WHERE p.roleId = :roleId")
    int softDeleteRoleById(@Param("roleId") UUID roleId);
    boolean existsByNameAndRoleIdNot(String name,UUID roleId);
    boolean existsByName(String name);
    @Query("SELECT r.deleted FROM Role r WHERE r.roleId = :roleId")
    Optional<Boolean> isRoleDeleted(UUID roleId);


}
