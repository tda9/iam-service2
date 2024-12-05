package com.da.iam.entity;

import com.da.iam.audit.entity.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.util.UUID;


@EqualsAndHashCode(callSuper = false)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "permissions")
@Entity
public class Permission extends BaseEntity {
    @Id
    @Column(name = "permission_id")
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID permissionId;
    @Column(name = "resource_name", nullable = false, unique = true)
    private String resourceName;
    @Column(name = "scope", nullable = false)
    @Enumerated(EnumType.STRING)
    private Scope scope;
    @Column(name = "resource_code", nullable = false)
    private String resourceCode;
    @Builder.Default
    @Column(name = "deleted", nullable = false)
    private boolean deleted = false;

}
