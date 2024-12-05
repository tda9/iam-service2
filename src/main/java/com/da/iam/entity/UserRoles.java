package com.da.iam.entity;

import com.da.iam.audit.entity.BaseEntity;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.UUID;

@Getter
@Setter
@Table(name = "user_roles")
@AllArgsConstructor
@NoArgsConstructor
@Entity
public class UserRoles extends BaseEntity {

    @Id
    @Column(name = "id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    @Column(name = "user_id")
    private UUID userId;
    @Column(name = "role_id")
    private UUID roleId;

}
