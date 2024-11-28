package com.da.iam.entity;

import com.da.iam.audit.entity.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.util.UUID;


@EqualsAndHashCode(callSuper = true)
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

    private String name;
    private boolean deleted;
}
