package com.da.iam.repo;

import com.da.iam.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDate;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepo extends JpaRepository<User, UUID> {

    boolean existsByEmail(String email);

    @Query("SELECT u.userId FROM User u WHERE u.email = :email")
    Optional<UUID> getUserIdByEmail(String email);
    Optional<User> findByEmail(String email);

    boolean existsByEmailAndUserIdNot(String email, UUID userId);
//    @Modifying
//    @Query()
//    int updateUserByUserId(String email, LocalDate dob, String phone, String )
}
