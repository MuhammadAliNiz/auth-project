package com.ali.authbackend.util;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import com.ali.authbackend.repository.RefreshTokenRepository;
import java.time.Instant;

@Slf4j
@Component
@RequiredArgsConstructor
public class TokenCleanupTask {

    private final RefreshTokenRepository refreshTokenRepository;

    @Scheduled(fixedRateString = "${jwt.refresh-token.cleanup-rate-ms}") // e.g., 86400000ms = 24 hours
    @Transactional
    public void purgeExpiredAndRevokedTokens() {
        log.info("Running refresh token cleanup task...");

        int deletedCount = refreshTokenRepository.deleteAllByRevokedTrueOrExpiryDateBefore(Instant.now());

        log.info("Deleted {} expired/revoked refresh tokens.", deletedCount);
    }
}