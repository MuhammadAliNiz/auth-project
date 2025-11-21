package com.ali.authbackend.repository;


import com.ali.authbackend.entity.RefreshToken;
import com.ali.authbackend.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {


    List<RefreshToken> findAllByUserAndRevokedFalse(User user);

    @Modifying
    int deleteAllByRevokedTrueOrExpiryDateBefore(Instant now);
}