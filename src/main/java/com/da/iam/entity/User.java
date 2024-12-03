package com.da.iam.entity;


import com.da.iam.audit.entity.BaseEntity;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDate;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@Data
@AllArgsConstructor
@Entity
@Table(name = "users")
@Builder
public class User extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "user_id")
    private UUID userId = UUID.randomUUID();
    private String username;
    private String firstName;
    private String lastName;
    private String email;
    private String password;
    private String phone;
    private LocalDate dob;
    private String image;
    @Builder.Default
    private boolean isLock = false;
    @Column(name = "is_verified")
    private boolean isVerified;
    @Builder.Default
    private boolean deleted = false;
    public User() {
        super();
    }
}
