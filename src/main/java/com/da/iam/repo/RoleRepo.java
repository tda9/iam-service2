package com.da.iam.repo;

import com.da.iam.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

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
}
