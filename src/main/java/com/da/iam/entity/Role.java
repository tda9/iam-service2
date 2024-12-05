package com.da.iam.entity;

import com.da.iam.audit.entity.BaseEntity;
import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.*;

import java.util.List;
import java.util.UUID;


@Setter
@Getter
@NoArgsConstructor
@Entity
@Table(name = "roles")
@Builder
@AllArgsConstructor
public class Role extends BaseEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "role_id")
    private UUID roleId;
    @Column(name = "name", nullable = false)
    private String name;
    @Builder.Default
    @Column(name = "deleted" ,nullable = false)
    private boolean deleted = false;
}
