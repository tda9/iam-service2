package com.da.iam.entity;

import com.da.iam.audit.entity.BaseEntity;
import jakarta.persistence.*;

import java.util.UUID;
@Table(name = "permissions")
@Entity
public class Permission extends BaseEntity {
    @Id
    @Column(name = "permission_id")
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID permissionId;
    private String name;
}
