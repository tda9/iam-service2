package com.da.iam.entity;


import com.da.iam.audit.entity.BaseEntity;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import jakarta.annotation.Nullable;
import jakarta.persistence.*;
import jakarta.validation.constraints.Size;
import lombok.*;

import java.time.LocalDate;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@EqualsAndHashCode(callSuper = false)
@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "users")
@Builder
public class User extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "user_id")
    private UUID userId = UUID.randomUUID();
    @Column(name = "email", nullable = false, unique = true)
    private String email;
    @Column(name = "username", nullable = true)
    private String username;
    @Column(name = "password", nullable = false)
    private String password;
    @Column(name = "first_name", nullable = true)
    private String firstName;
    @Column(name = "last_name", nullable = true)
    private String lastName;
    @Column(name = "phone", nullable = true)
    private String phone;
    @Column(name = "dob", nullable = true)
    private LocalDate dob;
    @Column(name = "image", nullable = true)
    private String image;
    @Builder.Default
    @Column(name = "is_lock", nullable = false)
    private boolean isLock = false;
    @Column(name = "is_verified", nullable = false)
    private boolean isVerified;
    @Builder.Default
    @Column(name = "deleted", nullable = false)
    private boolean deleted = false;

}
