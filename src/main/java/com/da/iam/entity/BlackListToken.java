package com.da.iam.entity;

import com.da.iam.audit.entity.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.UUID;

@Getter
@Setter
@Entity
@Table(name = "black_list_token")
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class BlackListToken extends BaseEntity {

    @Id
    @Column(name = "token_id")
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID tokenId;
    @Column(name = "user_id")
    private UUID userId;
    @Column(length = 10000)
    private String token;
    @Column(name = "expiration_date")
    private LocalDateTime expirationDate;


    public BlackListToken(String token,LocalDateTime expirationDate,UUID userId){
        this.token = token;
        this.expirationDate =expirationDate;
        this.userId = userId;
    }
}
