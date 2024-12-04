package com.da.iam.repo;

import com.da.iam.entity.User;
import com.da.iam.repo.impl.UserRepoCustom;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepo extends JpaRepository<User, UUID>, UserRepoCustom {

    boolean existsByEmail(String email);

    @Query("SELECT u.userId FROM User u WHERE u.email = :email")
    Optional<UUID> getUserIdByEmail(String email);
    Optional<User> findByEmail(String email);

    boolean existsByEmailAndUserIdNot(String email, UUID userId);
//    @Modifying
//    @Query()
//    int updateUserByUserId(String email, LocalDate dob, String phone, String )

//    @Query(value = "SELECT * FROM users u WHERE " +
//            "unaccent(u.email) ILIKE unaccent(:keyword) or "+
//            "unaccent(u.first_name) ILIKE unaccent(:keyword) or "+
//            "unaccent(u.last_name) ILIKE unaccent(:keyword) or "+
//            "unaccent(u.username) ILIKE unaccent(:keyword) "
//            , nativeQuery = true)


}
