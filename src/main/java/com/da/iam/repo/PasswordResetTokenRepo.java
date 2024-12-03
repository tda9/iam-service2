package com.da.iam.repo;

import com.da.iam.entity.PasswordResetToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface PasswordResetTokenRepo extends JpaRepository<PasswordResetToken, UUID> {
    PasswordResetToken findPasswordResetTokenByToken(String token);
    Optional<PasswordResetToken> findTopByUserIdOrderByCreatedDateDesc(UUID userId);
}
