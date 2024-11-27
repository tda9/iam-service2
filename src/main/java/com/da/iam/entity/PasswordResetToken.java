package com.da.iam.entity;

import com.da.iam.audit.entity.BaseEntity;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.UUID;

@Getter
@Setter
@AllArgsConstructor
@Entity
@Table(name = "password_reset_token")
public class PasswordResetToken extends BaseEntity {

    @Id
    @Column(name = "token_id")
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID tokenId;
    private String token;
    @Column(name = "expiration_date")
    private LocalDateTime expirationDate;
    @Column(name = "user_id")
    private Long userId;
    public PasswordResetToken() {
        super();
    }
}
