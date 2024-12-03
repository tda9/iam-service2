package com.da.iam.entity;

import com.da.iam.audit.entity.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.util.UUID;


@EqualsAndHashCode(callSuper = true)
@Data
@Builder

@AllArgsConstructor
@Table(name = "permissions")
@Entity
public class Permission extends BaseEntity {
    @Id
    @Column(name = "permission_id")
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID permissionId;
    @Column(name = "resource_name")
    private String resourceName;
    @Column(name = "scope")
    private String scope;
    @Column(name = "resource_code")
    private String resourceCode;
    private boolean deleted;
    //resource code(USER), scope(VIEW), resource name(QUAN LY NGUOI DUNG)

    public Permission(){
        super();
    }
}
