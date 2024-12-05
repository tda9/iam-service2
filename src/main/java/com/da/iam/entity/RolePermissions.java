package com.da.iam.entity;

import com.da.iam.audit.entity.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.util.UUID;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "role_permissions")
@Entity
@Builder
public class RolePermissions extends BaseEntity {
    @Id
    @Column(name = "id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    @Column(name = "role_id")
    private UUID roleId;
    @Column(name = "permission_id")
    private UUID permissionId;
    @Column(name = "resource_code")
    private String resourceCode;
    @Column(name = "scope")
    @Enumerated(EnumType.STRING)
    private Scope scope;
}
