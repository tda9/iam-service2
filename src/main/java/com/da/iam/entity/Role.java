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
    @Column(name = "role_id")
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID roleId;
    private String name;
    private boolean deleted;
}
